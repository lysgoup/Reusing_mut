use crate::{
    branches::GlobalBranches, command::CommandOpt, cond_stmt::NextState, depot::Depot,
    executor::Executor, fuzz_type::FuzzType, search::*, stats,
};
use rand::prelude::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, RwLock,
};
use crate::search::apply_reusing_mutation;

pub fn fuzz_loop(
    running: Arc<AtomicBool>,
    cmd_opt: CommandOpt,
    depot: Arc<Depot>,
    global_branches: Arc<GlobalBranches>,
    global_stats: Arc<RwLock<stats::ChartStats>>,
) {
    let search_method = cmd_opt.search_method;
    let mut executor = Executor::new(
        cmd_opt,
        global_branches,
        depot.clone(),
        global_stats.clone(),
    );

    while running.load(Ordering::Relaxed) {
        let entry = match depot.get_entry() {
            Some(e) => e,
            None => break,
        };

        let mut cond = entry.0;
        let priority = entry.1;

        if priority.is_done() {
            break;
        }

        if cond.is_done() {
            depot.update_entry(cond);
            continue;
        }

        trace!("{:?}", cond);

        let belong_input = cond.base.belong as usize;

        /*
        if config::ENABLE_PREFER_FAST_COND && cond.base.op == defs::COND_AFL_OP {
            let mut rng = thread_rng();
            let speed_ratio = depot.get_speed_ratio(belong_input);
            if speed_ratio > 1 {
                // [2, 3] -> 2
                // [4, 7] -> 3
                // [7, 15] -> 4
                // [16, ..] -> 5
                let weight = ((speed_ratio + 1) as f32).log2().ceil() as u32;
                if !rng.gen_weighted_bool(weight) {
                    continue;
                }
            }
        }
        */

        let buf = depot.get_input_buf(belong_input);

        {
            let fuzz_type = cond.get_fuzz_type();
            let mut handler = SearchHandler::new(running.clone(), &mut executor, &mut cond, buf);
            match fuzz_type {
                FuzzType::ExploreFuzz => {
                    let solved_by_reusing = apply_reusing_mutation(&mut handler, 100);

                    if solved_by_reusing {
                        info!("[FuzzLoop] Condition solved by reusing, skipping other mutations");
                        // ✅ 다른 mutation 건너뛰고 바로 다음 조건문으로
                    } else {
                        // 기존 mutation 계속 진행
                        if handler.cond.is_time_expired() {
                            handler.cond.next_state();
                        }
            
                        if handler.cond.state.is_one_byte() {
                            OneByteFuzz::new(handler).run();
                        } else if handler.cond.state.is_det() {
                            DetFuzz::new(handler).run();
                        } else {
                            match search_method {
                                SearchMethod::Gd => {
                                    GdSearch::new(handler).run(&mut thread_rng());
                                },
                                SearchMethod::Random => {
                                    RandomSearch::new(handler).run();
                                },
                                SearchMethod::Cbh => {
                                    CbhSearch::new(handler).run();
                                },
                                SearchMethod::Mb => {
                                    MbSearch::new(handler).run();
                                },
                            }
                        }
                    }
                },
                FuzzType::ExploitFuzz => {
                    let solved_by_reusing = apply_reusing_mutation(&mut handler, 100);
            
                    if !solved_by_reusing {
                        if handler.cond.state.is_one_byte() {
                            let mut fz = OneByteFuzz::new(handler);
                            fz.run();
                            fz.handler.cond.to_unsolvable();
                        } else {
                            ExploitFuzz::new(handler).run();
                        }
                    }
                },
                FuzzType::AFLFuzz => {
                    AFLFuzz::new(handler).run();
                },
                FuzzType::LenFuzz => {
                    LenFuzz::new(handler).run();
                },
                FuzzType::CmpFnFuzz => {
                    FnFuzz::new(handler).run();
                },
                FuzzType::OtherFuzz => {
                    warn!("Unknown fuzz type!!");
                },
            }
        }

        depot.update_entry(cond);
    }
}
