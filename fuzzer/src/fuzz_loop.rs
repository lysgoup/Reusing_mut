use crate::{
    branches::GlobalBranches, command::CommandOpt, cond_stmt::NextState, depot::Depot,
    executor::Executor, fuzz_type::FuzzType, search::*, stats,
};
use rand::prelude::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, RwLock,
};

pub fn fuzz_loop(
    running: Arc<AtomicBool>,
    cmd_opt: CommandOpt,
    depot: Arc<Depot>,
    global_branches: Arc<GlobalBranches>,
    global_stats: Arc<RwLock<stats::ChartStats>>,
) {
    let search_method = cmd_opt.search_method;
    let enable_reusing = cmd_opt.enable_reusing;
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
            executor.current_parent_input = belong_input;
            let mut handler = SearchHandler::new(running.clone(), &mut executor, &mut cond, buf);
            match fuzz_type {
                FuzzType::ExploreFuzz => {
                    // OneByte conds are already solved exhaustively (0..256, stops as
                    // soon as it flips) by OneByteFuzz below, so reusing's guesses can
                    // only add overhead here, not save work.
                    let reusing_outcome = if enable_reusing && !handler.cond.state.is_one_byte() {
                        handler.executor.current_mut_op = "Reusing";
                        ReusingFuzz::new(&mut handler).run(50)
                    } else {
                        ReusingOutcome::NoProgress
                    };

                    if reusing_outcome == ReusingOutcome::Solved {
                        info!("[FuzzLoop] Condition solved by reusing, skipping other mutations");
                    } else {
                        if handler.cond.is_time_expired() {
                            handler.cond.next_state();
                        }

                        // If reusing didn't solve it but left behind an improved buffer
                        // (best_f < MAX), tag whatever runs next as "Reusing+<op>" so
                        // analysis-mode can tell that discovery apart from one this
                        // search stage found entirely on its own.
                        let improved = reusing_outcome == ReusingOutcome::Improved;

                        if handler.cond.state.is_one_byte() {
                            handler.executor.current_mut_op = "OneByte";
                            OneByteFuzz::new(handler).run();
                        } else if handler.cond.state.is_det() {
                            handler.executor.current_mut_op = "Det";
                            DetFuzz::new(handler).run();
                        } else {
                            match search_method {
                                SearchMethod::Gd => {
                                    handler.executor.current_mut_op = if improved { "Reusing+GD" } else { "GD" };
                                    GdSearch::new(handler).run(&mut thread_rng());
                                },
                                SearchMethod::Random => {
                                    handler.executor.current_mut_op = if improved { "Reusing+Random" } else { "Random" };
                                    RandomSearch::new(handler).run();
                                },
                                SearchMethod::Cbh => {
                                    handler.executor.current_mut_op = if improved { "Reusing+Cbh" } else { "Cbh" };
                                    CbhSearch::new(handler).run();
                                },
                                SearchMethod::Mb => {
                                    handler.executor.current_mut_op = if improved { "Reusing+MB" } else { "MB" };
                                    MbSearch::new(handler).run();
                                },
                            }
                        }
                    }
                },
                FuzzType::ExploitFuzz => {
                    // Same reasoning as ExploreFuzz: OneByte is exhaustively covered
                    // by OneByteFuzz below, so skip reusing for it.
                    //
                    // Unlike ExploreFuzz, an ExploitFuzz cond isn't a branch to
                    // "solve" -- it's a sensitive function-call argument to bombard
                    // with extreme values looking for a crash. cond.is_done() (i.e.
                    // ReusingOutcome::Solved) reflects the Explore-style "output ==
                    // 0" signal, which doesn't mean "found the bug" here, so it must
                    // not be allowed to skip the actual exploitation attempt below.
                    if enable_reusing && !handler.cond.state.is_one_byte() {
                        handler.executor.current_mut_op = "Reusing";
                        ReusingFuzz::new(&mut handler).run(50);
                    }

                    if handler.cond.state.is_one_byte() {
                        handler.executor.current_mut_op = "OneByte";
                        let mut fz = OneByteFuzz::new(handler);
                        fz.run();
                        fz.handler.cond.to_unsolvable();
                    } else {
                        handler.executor.current_mut_op = "Exploit";
                        ExploitFuzz::new(handler).run();
                    }
                },
                FuzzType::AFLFuzz => {
                    handler.executor.current_mut_op = "AFL";
                    AFLFuzz::new(handler).run();
                },
                FuzzType::LenFuzz => {
                    handler.executor.current_mut_op = "Len";
                    LenFuzz::new(handler).run();
                },
                FuzzType::CmpFnFuzz => {
                    let solved_by_reusing = if enable_reusing {
                        handler.executor.current_mut_op = "Reusing";
                        ReusingFuzz::new(&mut handler).run(50) == ReusingOutcome::Solved
                    } else {
                        false
                    };
                    if !solved_by_reusing {
                        handler.executor.current_mut_op = "CmpFn";
                        FnFuzz::new(handler).run();
                    }
                },
                FuzzType::OtherFuzz => {
                    warn!("Unknown fuzz type!!");
                },
            }
        }

        depot.update_entry(cond);
    }
}
