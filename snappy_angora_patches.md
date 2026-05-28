# Snappy Angora Patch Report

**비교 대상**
- Before: `snappy_reusing_angora_original_reusing/`
- After: `snappy_reusing_angora_original_reusing_final/`

**수정 파일 목록 (10개)**

| # | 파일 경로 | 변경 범주 |
|---|-----------|-----------|
| 1 | `fuzzer/src/cond_stmt/cond_stmt.rs` | 구조체 필드 재설계 |
| 2 | `fuzzer/src/depot/reuse_pool.rs` | 풀 키 체계·용량 제한 강화 |
| 3 | `fuzzer/src/executor/executor.rs` | API 시그니처 동기화 |
| 4 | `fuzzer/src/fuzz_loop.rs` | Reusing 실행 흐름 통합 |
| 5 | `fuzzer/src/search/reusing.rs` | 크로스-세그먼트 샘플링 교정 |
| 6 | `fuzzer/src/track/fparser.rs` | 불필요한 필드 초기화 제거 |
| 7 | `llvm_mode/dfsan_rt/lib/dfsan/done_abilist.txt` | DFSan ABI 목록 정비 |
| 8 | `llvm_mode/external_lib/io_func.c` | I/O 후킹 커버리지 확대 |
| 9 | `llvm_mode/pass/AngoraPass/AngoraPass.cpp` | 디버그 로그 조건화 |
| 10 | `llvm_mode/rules/angora_abilist.txt` | Angora ABI 규칙 정비 |

---

## 수정 1: `fuzzer/src/cond_stmt/cond_stmt.rs` — `CondStmt` 구조체 필드 재설계

### 수정 목적

`reuse_offsets`, `reuse_offsets_opt` 필드는 `fparser.rs`에서 `union_merge(offsets)`를 호출하여 생성한 **파생 필드**로, 원본 `offsets` / `offsets_opt` 와 중복 정보를 가졌다. 이를 제거하여 구조체를 단순화하고, 대신 크로스-세그먼트(cross-segment) 재사용 시도 횟수를 추적하는 커서 필드(`reuse_cursor_cross`, `reuse_cursor_cross_opt`)를 추가해 중복 실행을 방지한다.

### 수정 전 코드

```rust
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct CondStmt {
    pub base: CondStmtBase,
    pub offsets: Vec<TagSeg>,
    pub offsets_opt: Vec<TagSeg>,
    pub reuse_offsets: Vec<TagSeg>,       // 파생 필드 (union_merge(offsets))
    pub reuse_offsets_opt: Vec<TagSeg>,   // 파생 필드 (union_merge(offsets_opt))
    pub reuse_merged_offsets: Vec<TagSeg>,
    // ...
    pub reuse_cursor: usize,
    pub reuse_cursor_opt: usize,
    pub reuse_cursor_merged: usize,
    // reuse_cursor_cross 없음
}

impl CondStmt {
    pub fn new() -> Self {
        Self {
            // ...
            reuse_offsets: vec![],
            reuse_offsets_opt: vec![],
            // ...
            // reuse_cursor_cross 초기화 없음
        }
    }
}
```

### 수정 후 코드

```rust
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct CondStmt {
    pub base: CondStmtBase,
    pub offsets: Vec<TagSeg>,
    pub offsets_opt: Vec<TagSeg>,
    // reuse_offsets, reuse_offsets_opt 제거
    pub reuse_merged_offsets: Vec<TagSeg>,
    // ...
    pub reuse_cursor: usize,
    pub reuse_cursor_opt: usize,
    pub reuse_cursor_merged: usize,
    pub reuse_cursor_cross: usize,        // 신규: cross-segment 커서
    pub reuse_cursor_cross_opt: usize,    // 신규: cross-segment opt 커서
}

impl CondStmt {
    pub fn new() -> Self {
        Self {
            // ...
            // reuse_offsets 관련 초기화 제거
            reuse_cursor_cross: 0,
            reuse_cursor_cross_opt: 0,
        }
    }
}
```

### 기대 효과

- 구조체 메모리 사용량 감소 (중복 `Vec<TagSeg>` 두 개 제거).
- 데이터 일관성 문제 원천 차단 (파생 필드와 원본 필드 간 불일치 불가).
- 크로스-세그먼트 재사용 횟수를 커서로 추적하여 동일 조건에 대한 과도한 반복 실행 방지.

---

## 수정 2: `fuzzer/src/depot/reuse_pool.rs` — 풀 키 체계 및 용량 제한 강화

### 수정 목적

**B-1** (풀 키 오염 방지): 기존 `HashMap<Vec<usize>, Vec<ReuseEntry>>`는 세그먼트 크기만 키로 사용하여 정수 비교(`icmp`), 부동소수점 비교(`fcmp`), 함수 비교(`fn_cmp`), AFL 타입 등 구조가 다른 비교의 바이트 패턴이 같은 버킷에 섞이는 **교차 오염** 문제가 있었다.

**B-2** (풀 용량 한계): 동일 크기 패턴에 대해 무한정 엔트리가 쌓여 메모리 폭증 및 순차 탐색(`get_at`) 비효율을 유발했다.

**B-3** (제거된 필드 참조): `add_from_conds`가 삭제된 `reuse_offsets`/`reuse_offsets_opt` 필드를 참조하고 있어 컴파일 오류 및 논리 오류 발생.

### 수정 전 코드

```rust
use angora_common::tag::TagSeg;

pub struct ReusePool {
    // Key: 세그먼트 크기만 (op 종류 무시 → 교차 오염)
    pool: Mutex<HashMap<Vec<usize>, Vec<ReuseEntry>>>,
}

impl ReusePool {
    pub fn add_from_conds(&self, cond_stmts: &[CondStmt], buf: &[u8]) {
        let mut pool = self.pool.lock().unwrap();
        for cond in cond_stmts {
            // 삭제된 reuse_offsets, reuse_offsets_opt 필드 참조
            for offsets in [&cond.reuse_offsets, &cond.reuse_offsets_opt] {
                if offsets.is_empty() { continue; }
                Self::insert_entry(&mut pool, offsets, buf, cond);
                // ...
            }
            if !cond.reuse_merged_offsets.is_empty() {
                Self::insert_entry(&mut pool, &cond.reuse_merged_offsets, buf, cond);
            }
        }
    }

    fn insert_entry(
        pool: &mut HashMap<Vec<usize>, Vec<ReuseEntry>>,
        offsets: &[TagSeg],
        buf: &[u8],
        cond: &CondStmt,
    ) {
        // ...
        let key: Vec<usize> = offsets.iter()
            .map(|seg| (seg.end - seg.begin) as usize)
            .collect();
        // ...
        let entries = pool.entry(key).or_insert_with(Vec::new);
        if entries.iter().any(|e| e.bytes == bytes) { return; }
        entries.push(ReuseEntry { ... });
        // 크기 제한 없음 → 무한 증가
    }

    pub fn get_at(&self, sizes: &[usize], index: usize) -> Option<Vec<u8>> {
        let pool = self.pool.lock().unwrap();
        let entries = pool.get(sizes)?;
        entries.get(index).map(|e| e.bytes.clone())
    }

    pub fn sample<R: Rng + ?Sized>(&self, sizes: &[usize], rng: &mut R) -> Option<Vec<u8>> {
        let pool = self.pool.lock().unwrap();
        let entries = pool.get(sizes)?;
        // ...
    }
}
```

### 수정 후 코드

```rust
use angora_common::{defs, tag::TagSeg};

const MAX_POOL_PER_KEY: usize = 200;

/// op 카테고리: 서로 다른 비교 유형이 같은 버킷에 섞이지 않도록 키 구성 요소로 추가
/// 0 = integer cmp, 1 = float cmp, 2 = fn cmp, 3 = AFL/other
fn op_category(op: u32) -> u8 {
    match op {
        defs::COND_FN_OP => 2,
        defs::COND_AFL_OP | defs::COND_LEN_OP => 3,
        o if o >= defs::COND_FCMP_FALSE && o <= defs::COND_FCMP_TRUE => 1,
        _ => 0,
    }
}

type PoolKey = (Vec<usize>, u8);  // (세그먼트 크기 목록, op 카테고리)

pub struct ReusePool {
    pool: Mutex<HashMap<PoolKey, Vec<ReuseEntry>>>,
}

impl ReusePool {
    pub fn add_from_conds(&self, cond_stmts: &[CondStmt], buf: &[u8]) {
        let mut pool = self.pool.lock().unwrap();
        for cond in cond_stmts {
            let op_cat = op_category(cond.base.op);
            // offsets / offsets_opt 직접 참조 (제거된 reuse_* 필드 제거)
            for offsets in [&cond.offsets, &cond.offsets_opt] {
                if offsets.is_empty() { continue; }
                Self::insert_entry(&mut pool, offsets, buf, cond, op_cat);
                if offsets.len() > 1 {
                    for seg in offsets.iter() {
                        Self::insert_entry(&mut pool, std::slice::from_ref(seg), buf, cond, op_cat);
                    }
                }
            }
            if !cond.reuse_merged_offsets.is_empty() {
                Self::insert_entry(&mut pool, &cond.reuse_merged_offsets, buf, cond, op_cat);
            }
        }
    }

    fn insert_entry(
        pool: &mut HashMap<PoolKey, Vec<ReuseEntry>>,
        offsets: &[TagSeg],
        buf: &[u8],
        cond: &CondStmt,
        op_cat: u8,
    ) {
        // ...
        let sizes: Vec<usize> = offsets.iter()
            .map(|seg| (seg.end - seg.begin) as usize)
            .collect();
        let key: PoolKey = (sizes, op_cat);
        // ...
        let entries = pool.entry(key).or_insert_with(Vec::new);
        if entries.iter().any(|e| e.bytes == bytes) { return; }

        // 신규: 저수지 샘플링으로 용량 제한 (MAX_POOL_PER_KEY = 200)
        if entries.len() >= MAX_POOL_PER_KEY {
            let idx = rand::thread_rng().gen_range(0..MAX_POOL_PER_KEY);
            entries[idx] = ReuseEntry { ... };
            return;
        }
        entries.push(ReuseEntry { ... });
    }

    pub fn get_at(&self, sizes: &[usize], op_cat: u8, index: usize) -> Option<Vec<u8>> {
        let pool = self.pool.lock().unwrap();
        let key = (sizes.to_vec(), op_cat);
        let entries = pool.get(&key)?;
        entries.get(index).map(|e| e.bytes.clone())
    }

    pub fn sample<R: Rng + ?Sized>(&self, sizes: &[usize], op_cat: u8, rng: &mut R) -> Option<Vec<u8>> {
        let pool = self.pool.lock().unwrap();
        let key = (sizes.to_vec(), op_cat);
        let entries = pool.get(&key)?;
        // ...
    }
}
```

### 기대 효과

- **교차 오염 제거**: 정수·부동소수점·함수 비교 등 다른 의미론적 구조를 갖는 바이트 패턴이 같은 풀 버킷에 섞이지 않아 재사용 정확도 향상.
- **메모리 상한 보장**: 키당 최대 200개 엔트리로 제한되며, 초과 시 무작위 교체(저수지 샘플링)로 풀의 다양성 유지.
- **컴파일 오류 수정**: 삭제된 `reuse_offsets` 필드 참조 제거.
- **dump 출력 개선**: 디버그 파일에 op 카테고리 정보 포함.

---

## 수정 3: `fuzzer/src/executor/executor.rs` — API 시그니처 동기화

### 수정 목적

`reuse_pool.rs`의 `get_at` / `sample`에 `op_cat: u8` 파라미터가 추가됨에 따라 이를 위임하는 `executor.rs`의 래퍼 메서드 시그니처를 동기화한다.

### 수정 전 코드

```rust
pub fn get_reuse_at(&self, sizes: &[usize], index: usize) -> Option<Vec<u8>> {
    self.depot.reuse_pool.get_at(sizes, index)
}

pub fn sample_reuse<R: Rng + ?Sized>(&self, sizes: &[usize], rng: &mut R) -> Option<Vec<u8>> {
    self.depot.reuse_pool.sample(sizes, rng)
}
```

### 수정 후 코드

```rust
pub fn get_reuse_at(&self, sizes: &[usize], op_cat: u8, index: usize) -> Option<Vec<u8>> {
    self.depot.reuse_pool.get_at(sizes, op_cat, index)
}

pub fn sample_reuse<R: Rng + ?Sized>(&self, sizes: &[usize], op_cat: u8, rng: &mut R) -> Option<Vec<u8>> {
    self.depot.reuse_pool.sample(sizes, op_cat, rng)
}
```

### 기대 효과

- `reuse_pool`의 키 체계 변경과 완전 일치하여 컴파일 오류 없이 `op_cat` 기반 풀 조회 가능.

---

## 수정 4: `fuzzer/src/fuzz_loop.rs` — Reusing 실행 흐름 통합

### 수정 목적

기존 코드는 세 가지 타깃(Offsets, OffsetsOpt, MergedOffsets) 각각에 대해 **별도 `SearchHandler`를 3번 생성**하고, 매번 `depot.get_input_buf()`를 호출했다. 또한 삭제된 `reuse_offsets`/`reuse_offsets_opt` 필드를 가드 조건으로 사용했다. 이를 단일 핸들러·단일 버퍼 획득으로 통합하고 가드 조건을 올바른 필드(`offsets`, `offsets_opt`)로 교체한다.

### 수정 전 코드

```rust
if !depot.reuse_pool.is_empty() {
    let saved_fuzz_times = cond.fuzz_times;
    let saved_state = cond.state.clone();
    let saved_speed = cond.speed;

    // 삭제된 필드로 가드 + 핸들러 3회 생성
    if !cond.reuse_offsets.is_empty() {
        let buf2 = depot.get_input_buf(belong_input);
        executor.current_fuzz_type = FuzzType::ReusingFuzz;
        let handler = SearchHandler::new(running.clone(), &mut executor, &mut cond, buf2);
        ReusingFuzz::new(handler).run(rng, ReuseTarget::Offsets);
    }
    if !cond.reuse_offsets_opt.is_empty() {
        let buf2 = depot.get_input_buf(belong_input);
        executor.current_fuzz_type = FuzzType::ReusingFuzz;
        let handler = SearchHandler::new(running.clone(), &mut executor, &mut cond, buf2);
        ReusingFuzz::new(handler).run(rng, ReuseTarget::OffsetsOpt);
    }
    if !cond.reuse_merged_offsets.is_empty() {
        let buf2 = depot.get_input_buf(belong_input);
        executor.current_fuzz_type = FuzzType::ReusingFuzz;
        let handler = SearchHandler::new(running.clone(), &mut executor, &mut cond, buf2);
        ReusingFuzz::new(handler).run(rng, ReuseTarget::MergedOffsets);
    }

    cond.fuzz_times = saved_fuzz_times;
    cond.state = saved_state;
    cond.speed = saved_speed;
}
```

### 수정 후 코드

```rust
// 올바른 필드로 가드 조건 구성 (reuse_offsets 제거됨)
let has_reuse = !depot.reuse_pool.is_empty()
    && (!cond.offsets.is_empty()
        || !cond.offsets_opt.is_empty()
        || !cond.reuse_merged_offsets.is_empty());
if has_reuse {
    let saved_fuzz_times = cond.fuzz_times;
    let saved_state = cond.state.clone();
    let saved_speed = cond.speed;

    // 핸들러 1회 생성 + run_all()로 세 타깃 순차 처리
    let buf_reuse = depot.get_input_buf(belong_input);
    executor.current_fuzz_type = FuzzType::ReusingFuzz;
    let handler = SearchHandler::new(running.clone(), &mut executor, &mut cond, buf_reuse);
    ReusingFuzz::new(handler).run_all(rng);

    cond.fuzz_times = saved_fuzz_times;
    cond.state = saved_state;
    cond.speed = saved_speed;
}
```

### 기대 효과

- `SearchHandler`·버퍼 획득 비용을 3회 → 1회로 절감.
- 삭제된 필드 참조 오류 수정 (컴파일 오류 방지).
- 핸들러 내부에서 중간에 중단 조건이 발생하면 후속 타깃을 자동 건너뛰어 불필요한 실행 제거.

---

## 수정 5: `fuzzer/src/search/reusing.rs` — 크로스-세그먼트 샘플링 교정

### 수정 목적

**B-3** (삭제된 필드): `reuse_offsets`/`reuse_offsets_opt` 필드 직접 참조를 원본 `offsets`/`offsets_opt`로 교체.

**B-4** (크로스-세그먼트 샘플링 오류): 기존 크로스-세그먼트 재사용은 각 세그먼트를 **독립적으로** 샘플링하여 연결했다. 이는 조건 내 바이트 간 상관관계를 파괴하고, 풀 키 불일치(`[s1]`+`[s2]` vs `[s1,s2]`)를 유발한다. 또한 크로스 시도 횟수(`cross_cursor`)를 추적하지 않아 매 퍼즈 라운드마다 50회씩 반복 실행되었다.

**B-new** (`run_all` 메서드): 외부에서 세 타깃을 직접 호출하던 방식을 캡슐화하여, 핸들러를 재사용하면서 순차적으로 처리하고 중단 조건을 존중한다.

### 수정 전 코드

```rust
use crate::{fuzz_type::FuzzType, mut_input::MutInput};
use super::SearchHandler;
use rand::prelude::*;

pub fn run<R: Rng + ?Sized>(&mut self, rng: &mut R, target: ReuseTarget) {
    // 삭제된 필드 직접 참조
    let reuse_offsets = match target {
        ReuseTarget::Offsets    => self.handler.cond.reuse_offsets.clone(),
        ReuseTarget::OffsetsOpt => self.handler.cond.reuse_offsets_opt.clone(),
        ReuseTarget::MergedOffsets => self.handler.cond.reuse_merged_offsets.clone(),
    };
    // ...

    // Cross-segment: 각 세그먼트를 독립 샘플링 후 연결 (관계 파괴)
    for _ in 0..50 {  // 커서 없이 매 라운드 50회 고정
        if self.handler.is_stopped_or_skip() { break; }
        let mut combined = Vec::new();
        let mut any_empty = false;
        for seg in &reuse_offsets {
            let seg_size = [(seg.end - seg.begin) as usize];
            // 각 세그먼트를 별도 키([s_i])로 샘플링 → 관계 파괴
            match self.handler.executor.sample_reuse(&seg_size, rng) {
                Some(bytes) => combined.extend_from_slice(&bytes),
                None => { any_empty = true; break; }
            }
        }
        if any_empty { break; }
        input.assign(&combined);
        self.handler.execute_input_at_ignore_skip(&input, &reuse_offsets);
    }
}
// run_all() 메서드 없음
```

### 수정 후 코드

```rust
use crate::{fuzz_type::FuzzType, mut_input::MutInput};
use super::SearchHandler;
use angora_common::defs;
use rand::prelude::*;

/// op 카테고리 (reuse_pool::op_category와 동일 로직)
fn op_category(op: u32) -> u8 {
    match op {
        defs::COND_FN_OP => 2,
        defs::COND_AFL_OP | defs::COND_LEN_OP => 3,
        o if o >= defs::COND_FCMP_FALSE && o <= defs::COND_FCMP_TRUE => 1,
        _ => 0,
    }
}

pub fn run<R: Rng + ?Sized>(&mut self, rng: &mut R, target: ReuseTarget) {
    // B-3: offsets/offsets_opt 직접 참조
    let reuse_offsets = match target {
        ReuseTarget::Offsets    => self.handler.cond.offsets.clone(),
        ReuseTarget::OffsetsOpt => self.handler.cond.offsets_opt.clone(),
        ReuseTarget::MergedOffsets => self.handler.cond.reuse_merged_offsets.clone(),
    };
    // ...
    let op_cat = op_category(self.handler.cond.base.op);
    // ...

    // Sequential: op_cat 포함 키로 조회
    match self.handler.executor.get_reuse_at(&sizes, op_cat, cursor) { ... }
    // ...

    // Cross-segment: B-4 수정
    const MAX_CROSS: usize = 50;
    if matches!(target, ReuseTarget::Offsets | ReuseTarget::OffsetsOpt)
        && reuse_offsets.len() > 1
    {
        let cross_cursor = match target {
            ReuseTarget::Offsets    => self.handler.cond.reuse_cursor_cross,
            ReuseTarget::OffsetsOpt => self.handler.cond.reuse_cursor_cross_opt,
            _ => unreachable!(),
        };
        let remaining = MAX_CROSS.saturating_sub(cross_cursor);
        let mut done = 0usize;
        for _ in 0..remaining {
            if self.handler.is_stopped_or_skip() { break; }
            // B-4: 결합 키([s1,s2,...], op_cat)로 단일 샘플링 → 바이트 관계 보존
            match self.handler.executor.sample_reuse(&sizes, op_cat, rng) {
                Some(combined) => {
                    input.assign(&combined);
                    self.handler.execute_input_at_ignore_skip(&input, &reuse_offsets);
                    done += 1;
                },
                None => break,
            }
        }
        // 커서 갱신으로 다음 라운드에서 중복 실행 방지
        match target {
            ReuseTarget::Offsets    => self.handler.cond.reuse_cursor_cross += done,
            ReuseTarget::OffsetsOpt => self.handler.cond.reuse_cursor_cross_opt += done,
            _ => unreachable!(),
        }
    }
}

/// 신규: 세 타깃을 단일 핸들러로 순차 실행 (중단 조건 존중)
pub fn run_all<R: Rng + ?Sized>(&mut self, rng: &mut R) {
    if !self.handler.cond.offsets.is_empty() {
        self.run(rng, ReuseTarget::Offsets);
    }
    if !self.handler.is_stopped_or_skip() && !self.handler.cond.offsets_opt.is_empty() {
        self.run(rng, ReuseTarget::OffsetsOpt);
    }
    if !self.handler.is_stopped_or_skip() && !self.handler.cond.reuse_merged_offsets.is_empty() {
        self.run(rng, ReuseTarget::MergedOffsets);
    }
}
```

### 기대 효과

- **바이트 관계 보존**: 결합 키 샘플링으로 동일 조건에서 수집된 여러 세그먼트의 바이트가 함께 적용되어 조건 만족 가능성 향상.
- **크로스 반복 중복 방지**: `reuse_cursor_cross` 커서로 이미 시도한 횟수를 추적, 동일 조건에 대한 무한 반복 차단.
- **핸들러 재사용**: `run_all`이 중단 신호(`is_stopped_or_skip`)를 확인하며 순차 실행하여 불필요한 타깃 건너뜀.

---

## 수정 6: `fuzzer/src/track/fparser.rs` — 불필요한 파생 필드 초기화 제거

### 수정 목적

`CondStmt`에서 `reuse_offsets`/`reuse_offsets_opt` 필드가 삭제되었으므로, 이 필드를 초기화하던 `union_merge` 호출과 관련 `use` 임포트를 제거한다.

### 수정 전 코드

```rust
use crate::mut_input::offsets::{union_merge, union_merge_two};

// cond 파싱 후:
cond.reuse_offsets     = union_merge(&cond.offsets);      // 파생 필드 초기화
cond.reuse_offsets_opt = union_merge(&cond.offsets_opt);  // 파생 필드 초기화
if !cond.offsets.is_empty() || !cond.offsets_opt.is_empty() {
    cond.reuse_merged_offsets = union_merge_two(&cond.offsets, &cond.offsets_opt);
}
```

### 수정 후 코드

```rust
use crate::mut_input::offsets::union_merge_two;  // union_merge 임포트 제거

// cond 파싱 후:
// reuse_offsets, reuse_offsets_opt 초기화 코드 전체 삭제
if !cond.offsets.is_empty() || !cond.offsets_opt.is_empty() {
    cond.reuse_merged_offsets = union_merge_two(&cond.offsets, &cond.offsets_opt);
}
```

### 기대 효과

- 파생 필드 제거에 따른 파싱 단계에서의 연산 비용 절감 (`union_merge` 2회 호출 제거).
- 미사용 임포트 정리로 컴파일 경고 해소.

---

## 수정 7: `llvm_mode/dfsan_rt/lib/dfsan/done_abilist.txt` — DFSan ABI 목록 정비

### 수정 목적

- `open` 함수에 대해 `uninstrumented` 규칙을 추가하여 DFSan 계측 전에 먼저 uninstrumented 처리가 적용되도록 순서를 명시한다.
- `__ctype_toupper_loc`, `longjmp` 함수에 `discard` 규칙을 추가하여 이들 함수가 DFSan 계측 중 문제를 일으키지 않도록 한다.

### 수정 전 코드 (`done_abilist.txt` 129번째 줄 부근)

```
# fun:open=discard
```

### 수정 후 코드

```
fun:open=uninstrumented
fun:open=discard
...
fun:__ctype_toupper_loc=discard
fun:longjmp=discard
```

### 기대 효과

- `open` 호출 시 DFSan의 계측/레이블 전파가 바이패스되어 파일 디스크립터 처리 안정성 향상.
- `longjmp`의 `discard` 처리로 비지역 점프 관련 DFSan 계측 충돌 방지.
- `__ctype_toupper_loc`의 `discard`로 glibc 내부 함수 관련 계측 오류 방지.

---

## 수정 8: `llvm_mode/external_lib/io_func.c` — I/O 후킹 커버리지 확대

### 수정 목적

`pread64` 시스템 콜과 `getc` 표준 라이브러리 함수에 대한 DFSan 래퍼가 없어, 이 함수로 퍼징 대상 파일을 읽을 때 오프셋 기반 taint 레이블이 할당되지 않는 문제를 해결한다.

### 수정 전 코드

```c
// __dfsw_pread64 없음 → pread64로 파일 읽기 시 taint 미할당

// __dfsw_getc 없음 → getc로 퍼징 파일 읽을 때 taint 미할당
// (__dfsw__IO_getc는 존재하지만 getc의 직접 래퍼 없음)
```

### 수정 후 코드

```c
// pread64 래퍼: pread와 동일한 taint 할당 로직으로 위임
__attribute__((visibility("default"))) ssize_t
__dfsw_pread64(int fd, void *buf, size_t count, off_t offset,
               dfsan_label fd_label, dfsan_label buf_label,
               dfsan_label count_label, dfsan_label offset_label,
               dfsan_label *ret_label) {
  return __dfsw_pread(fd, buf, count, offset,
                      fd_label, buf_label, count_label, offset_label,
                      ret_label);
}

// getc 래퍼: fgetc와 동일한 taint 할당 로직
__attribute__((visibility("default"))) int
__dfsw_getc(FILE *fd, dfsan_label fd_label, dfsan_label *ret_label) {
  long offset = ftell(fd);
  int c = getc(fd);
  *ret_label = 0;
#ifdef DEBUG_INFO
  fprintf(stderr, "### getc %p, range is %ld, 1 , c is %d\n", fd, offset, c);
#endif
  if (is_fuzzing_ffd(fd) && c != EOF) {
    dfsan_label l = dfsan_create_label(offset);
    *ret_label = l;
  }
  return c;
}
```

### 기대 효과

- `pread64`/`getc`로 입력을 읽는 대상 프로그램(snappy 등)에서도 바이트 오프셋 기반 taint 레이블이 정확히 할당됨.
- 계측 누락 없이 더 많은 분기 조건에 taint 정보가 전파되어 퍼징 탐색 깊이 향상.
- `pread64`는 `pread`와 시스템 수준에서 동일하므로 기존 로직 재사용으로 코드 중복 최소화.

---

## 수정 9: `llvm_mode/pass/AngoraPass/AngoraPass.cpp` — 디버그 로그 조건화

### 수정 목적

LLVM 패스가 CMP ID 로그를 기록한 후 **무조건** `errs()`(표준 에러)로 파일 경로를 출력하던 코드를, `LLVM_DEBUG` 매크로로 감싸 `-debug` 플래그 없이는 출력되지 않도록 변경한다.

### 수정 전 코드

```cpp
// Print the path of the log file after each successful write for traceability.
{
    const char *LogDir = getenv("ANGORA_PASS_LOG_DIR");
    errs() << "[AngoraPass] Wrote to: " << (LogDir ? LogDir : "?") << "/"
           << (FastMode ? "cmpid_log_fast.json" : "cmpid_log_track.json") << "\n";
}
```

### 수정 후 코드

```cpp
LLVM_DEBUG({
    const char *LogDir = getenv("ANGORA_PASS_LOG_DIR");
    dbgs() << "[AngoraPass] Wrote to: " << (LogDir ? LogDir : "?") << "/"
           << (FastMode ? "cmpid_log_fast.json" : "cmpid_log_track.json") << "\n";
});
```

### 기대 효과

- 일반 빌드 시 불필요한 stderr 출력 억제, 빌드 로그 오염 방지.
- `-debug` 또는 `-debug-only=AngoraPass` 플래그를 사용할 때만 출력되어 디버깅 편의성 유지.
- LLVM 디버그 출력 관례(`dbgs()`)와 통일.

---

## 수정 10: `llvm_mode/rules/angora_abilist.txt` — Angora ABI 규칙 정비

### 수정 목적

- `open`: 기존 `custom` 처리(Angora 커스텀 래퍼 사용)를 `uninstrumented` + `discard`로 변경하여 DFSan이 `open`의 반환값(fd)에 레이블을 붙이지 않도록 한다.
- `getc` / `pread64`: 새로 추가된 DFSan 래퍼(`__dfsw_getc`, `__dfsw_pread64`)를 활성화하기 위해 `uninstrumented` + `custom` 규칙을 추가한다.

### 수정 전 코드

```
fun:open=custom          # custom 래퍼로 처리
# fun:getc=uninstrumented
# fun:getc=custom        # 비활성화 상태
# pread64 규칙 없음
```

### 수정 후 코드

```
fun:open=uninstrumented  # fd에 레이블 전파 차단
fun:open=discard

fun:getc=uninstrumented  # getc: 커스텀 taint 래퍼 활성화
fun:getc=custom

fun:pread64=uninstrumented  # pread64: 커스텀 taint 래퍼 활성화
fun:pread64=custom
```

### 기대 효과

- `open` 반환값(파일 디스크립터 번호)이 taint 레이블을 가지지 않아, fd 값 자체가 계측 경로에 의도치 않게 영향을 주는 현상 방지.
- `getc`/`pread64`에 대한 커스텀 래퍼 규칙 활성화로 수정 8(`io_func.c`)과 연동, taint 전파 완성.

---

## 전체 수정 요약

### 변경 계층 구조

```
llvm_mode (계측 레이어)
 ├── done_abilist.txt      open 처리 정비, longjmp/ctype 안정화
 ├── angora_abilist.txt    open/getc/pread64 ABI 규칙 정비
 ├── io_func.c             pread64/getc taint 래퍼 추가
 └── AngoraPass.cpp        디버그 로그 조건화

fuzzer (퍼저 코어)
 ├── cond_stmt.rs          CondStmt 구조체 정리 (파생 필드 제거 + 크로스 커서 추가)
 ├── reuse_pool.rs         풀 키에 op_cat 추가 + 용량 제한 + offsets 직접 참조
 ├── executor.rs           get_reuse_at/sample_reuse API 시그니처 동기화
 ├── fuzz_loop.rs          단일 핸들러로 reusing 실행 통합
 ├── reusing.rs            크로스 샘플링 교정 + run_all 추가
 └── fparser.rs            reuse_offsets 파생 필드 초기화 코드 제거
```

### 핵심 개선 효과

| 개선 항목 | 기존 문제 | 개선 후 |
|-----------|-----------|---------|
| 풀 키 오염 | op 종류 무관 동일 버킷 | `(sizes, op_cat)` 키로 분리 |
| 풀 용량 무한 증가 | 제한 없음 | 키당 최대 200개, 초과 시 랜덤 교체 |
| 크로스-세그먼트 샘플링 | 세그먼트별 독립 샘플 → 관계 파괴 | 결합 키로 단일 샘플 → 관계 보존 |
| 크로스 반복 중복 | 매 라운드 최대 50회 | 커서 추적으로 중복 방지 |
| 핸들러 중복 생성 | 타깃별 별도 생성 3회 | `run_all()`로 1회 생성 후 순차 처리 |
| taint 커버리지 누락 | `pread64`/`getc` 미지원 | 래퍼 추가로 완전 지원 |
| 불필요한 stderr 출력 | 무조건 패스 로그 출력 | `LLVM_DEBUG`로 조건부 출력 |
