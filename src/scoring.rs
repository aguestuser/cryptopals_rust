use ordered_float::OrderedFloat;
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
use std::cmp::Ordering;

#[derive(Debug)]
pub struct ScoredCleartext {
    pub cleartext: Vec<u8>,
    pub score: f64,
}

impl ScoredCleartext {
    fn empty() -> ScoredCleartext {
        Self {
            cleartext: Vec::<u8>::new(),
            score: std::f64::MAX,
        }
    }
}

impl Eq for ScoredCleartext {}

impl PartialEq for ScoredCleartext {
    fn eq(&self, other: &ScoredCleartext) -> bool {
        self.score == other.score
    }
}

impl Ord for ScoredCleartext {
    fn cmp(&self, other: &ScoredCleartext) -> Ordering {
        OrderedFloat(self.score).cmp(&OrderedFloat(other.score))
    }
}

impl PartialOrd for ScoredCleartext {
    fn partial_cmp(&self, other: &ScoredCleartext) -> Option<Ordering> {
        Some(self.cmp(&other))
    }
}

#[derive(Debug)]
pub struct ScoredCleartextBlocks(pub Vec<ScoredCleartext>);

impl ScoredCleartextBlocks {
    pub fn empty() -> ScoredCleartextBlocks {
        Self(vec![ScoredCleartext::empty()])
    }

    pub fn sum(&self) -> f64 {
        self.0
            .par_iter()
            .map(|ScoredCleartext { score, .. }| score)
            .sum()
    }

    pub fn into_blocks(self) -> Vec<Vec<u8>> {
        self.0.into_par_iter().map(|sc| sc.cleartext).collect()
    }
}

impl Eq for ScoredCleartextBlocks {}

impl PartialEq for ScoredCleartextBlocks {
    fn eq(&self, other: &ScoredCleartextBlocks) -> bool {
        self.sum() == other.sum()
    }
}

impl Ord for ScoredCleartextBlocks {
    fn cmp(&self, other: &ScoredCleartextBlocks) -> Ordering {
        OrderedFloat(self.sum()).cmp(&OrderedFloat(other.sum()))
    }
}

impl PartialOrd for ScoredCleartextBlocks {
    fn partial_cmp(&self, other: &ScoredCleartextBlocks) -> Option<Ordering> {
        Some(self.cmp(&other))
    }
}

#[cfg(test)]
mod scoring_tests {
    use super::*;
    use std::cmp;

    #[test]
    fn constructing_an_empty_scored_cleartext() {
        assert_eq!(
            ScoredCleartext::empty(),
            ScoredCleartext {
                cleartext: Vec::<u8>::new(),
                score: std::f64::MAX,
            }
        )
    }

    #[test]
    fn comparing_two_unequal_scores() {
        let score1 = ScoredCleartext {
            cleartext: vec![0],
            score: 1.0,
        };
        let score2 = ScoredCleartext {
            cleartext: vec![0],
            score: 2.0,
        };

        assert_eq!(cmp::min(&score1, &score2), &score1);
    }

    #[test]
    fn comparing_two_equal_scores() {
        let score1 = ScoredCleartext {
            cleartext: vec![0],
            score: 1.0,
        };
        let score2 = ScoredCleartext {
            cleartext: vec![1],
            score: 1.0,
        };

        assert_eq!(score1, score2);
    }

    #[test]
    fn summing_a_vec_of_scores() {
        let scores = ScoredCleartextBlocks(vec![
            ScoredCleartext {
                cleartext: vec![0],
                score: 1.0,
            },
            ScoredCleartext {
                cleartext: vec![0],
                score: 2.0,
            },
            ScoredCleartext {
                cleartext: vec![0],
                score: 3.0,
            },
        ]);
        assert_eq!(scores.sum(), 6.0);
    }

    #[test]
    fn comparing_two_equal_vecs_of_scores() {
        // summed score of 10
        let scores1 = ScoredCleartextBlocks(vec![
            ScoredCleartext {
                cleartext: vec![0],
                score: 1.0,
            },
            ScoredCleartext {
                cleartext: vec![0],
                score: 2.0,
            },
            ScoredCleartext {
                cleartext: vec![0],
                score: 3.0,
            },
        ]);
        // summed score of 15
        let scores2 = ScoredCleartextBlocks(vec![
            ScoredCleartext {
                cleartext: vec![0],
                score: 2.0,
            },
            ScoredCleartext {
                cleartext: vec![0],
                score: 2.0,
            },
            ScoredCleartext {
                cleartext: vec![0],
                score: 2.0,
            },
        ]);

        assert_eq!(scores1, scores2);
    }

    #[test]
    fn comparing_two_vecs_of_unequal_scores() {
        // summed score of 10
        let scores1 = ScoredCleartextBlocks(vec![
            ScoredCleartext {
                cleartext: vec![0],
                score: 8.0,
            },
            ScoredCleartext {
                cleartext: vec![0],
                score: 1.0,
            },
            ScoredCleartext {
                cleartext: vec![0],
                score: 1.0,
            },
        ]);
        // summed score of 15
        let scores2 = ScoredCleartextBlocks(vec![
            ScoredCleartext {
                cleartext: vec![0],
                score: 5.0,
            },
            ScoredCleartext {
                cleartext: vec![0],
                score: 5.0,
            },
            ScoredCleartext {
                cleartext: vec![0],
                score: 5.0,
            },
        ]);

        assert_eq!(cmp::min(&scores1, &scores2), &scores1);
    }

    #[test]
    fn extracting_raw_bytes_from_cleartext_blocks() {
        let scores = ScoredCleartextBlocks(vec![
            ScoredCleartext {
                cleartext: vec![1, 2, 3],
                score: 8.0,
            },
            ScoredCleartext {
                cleartext: vec![4, 5, 6],
                score: 1.0,
            },
            ScoredCleartext {
                cleartext: vec![7, 8, 9],
                score: 1.0,
            },
        ]);
        assert_eq!(
            scores.into_blocks(),
            vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]]
        );
    }
}
