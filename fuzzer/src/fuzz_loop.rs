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
                    let solved_by_reusing = if enable_reusing {
                        handler.executor.current_mut_op = "Reusing";
                        apply_reusing_mutation(&mut handler, 50)
                    } else {
                        false
                    };

                    if solved_by_reusing {
                        info!("[FuzzLoop] Condition solved by reusing, skipping other mutations");
                    } else {
                        if handler.cond.is_time_expired() {
                            handler.cond.next_state();
                        }

                        if handler.cond.state.is_one_byte() {
                            handler.executor.current_mut_op = "OneByte";
                            OneByteFuzz::new(handler).run();
                        } else if handler.cond.state.is_det() {
                            handler.executor.current_mut_op = "Det";
                            DetFuzz::new(handler).run();
                        } else {
                            match search_method {
                                SearchMethod::Gd => {
                                    handler.executor.current_mut_op = "GD";
                                    GdSearch::new(handler).run(&mut thread_rng());
                                },
                                SearchMethod::Random => {
                                    handler.executor.current_mut_op = "Random";
                                    RandomSearch::new(handler).run();
                                },
                                SearchMethod::Cbh => {
                                    handler.executor.current_mut_op = "Cbh";
                                    CbhSearch::new(handler).run();
                                },
                                SearchMethod::Mb => {
                                    handler.executor.current_mut_op = "MB";
                                    MbSearch::new(handler).run();
                                },
                            }
                        }
                    }
                },
                FuzzType::ExploitFuzz => {
                    let solved_by_reusing = if enable_reusing {
                        handler.executor.current_mut_op = "Reusing";
                        apply_reusing_mutation(&mut handler, 50)
                    } else {
                        false
                    };

                    if !solved_by_reusing {
                        if handler.cond.state.is_one_byte() {
                            handler.executor.current_mut_op = "OneByte";
                            let mut fz = OneByteFuzz::new(handler);
                            fz.run();
                            fz.handler.cond.to_unsolvable();
                        } else {
                            handler.executor.current_mut_op = "Exploit";
                            ExploitFuzz::new(handler).run();
                        }
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
                    handler.executor.current_mut_op = "CmpFn";
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
