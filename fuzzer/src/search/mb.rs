// Magic bytes with random search

use super::*;
pub struct MbSearch<'a> {
    handler: SearchHandler<'a>,
}

impl<'a> MbSearch<'a> {
    pub fn new(handler: SearchHandler<'a>) -> Self {
        Self { handler }
    }

    pub fn run(&mut self) {
        // Record mutated offsets
        let offsets = self.handler.cond.offsets.clone();
        for seg in &offsets {
            self.handler.record_mutated_range(seg.begin as usize, seg.end as usize);
        }

        let mut input = self.handler.get_f_input();
        assert!(
            input.len() > 0,
            "Input length < 0!! {:?}",
            self.handler.cond
        );
        let orig_input_val = input.get_value();
        {
            // magic bytes
            input.assign(&self.handler.cond.variables);
            self.handler.execute_cond(&input);
        }

        loop {
            if self.handler.is_stopped_or_skip() {
                break;
            }
            input.assign(&orig_input_val);
            input.randomize_all();
            self.handler.execute_cond(&input);
        }
    }
}
