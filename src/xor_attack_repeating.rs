use crate::scoring::{ScoredCleartext, ScoredCleartextBlocks};
use crate::xor_attack;
use crate::xor_cypher;
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelIterator,
};
const NUM_KEYSIZE_GUESSES: usize = 2;
const NUM_HAMMING_DIST_SAMPLES: usize = 30;
const MIN_KEYSIZE: usize = 2;
const MAX_KEYSIZE: usize = 40;

#[derive(Clone, PartialEq, Debug)]
struct KeysizeDistance {
    keysize: usize,
    dist: f32,
}

/// given a `cyphertext`:
/// 1. guess the 4 most likely repeating-key XOR keysizes by comparing the edit distance
////   between the first 20 keysize-length blocks of the cyphertext
/// 2. for each likely keysize, partition the cyphertext into keysize-length blocks,
///    transpose the blocks into keysize-number blocks, perform brute force xor decryption
///    on each block (each of which will have a different key), then identify the correct cleartext
///    by picking the collection of transposed blocks with the lowest overall deviation
///    from ground-truth char frequency
/// 3. unpartition, un-tranpose, and encode the cleartext blocks to produce the decryptd cleartext
pub fn brute_force_decrypt(cyphertext: &[u8]) -> String {
    let keysizes = guess_keysizes(cyphertext);
    let transposed_cleartext_blocks = minscore_transposed_cleartext_blocks(cyphertext, keysizes);
    let cleartext_bytes = unpartition(transpose_owned(transposed_cleartext_blocks));
    String::from_utf8_lossy(&cleartext_bytes).to_string()
}

/// given a vec of N `likely_keysizes` and a `cyphertext`
/// 1. produce a vec of N vecs of partioned/transposed cyphertext blocks
/// 2. consider each cyphertext block as a message and decrypt it via brute force xor guessing
///    producing a vec of N vecs of partioned/transposed cleartext blocks
/// 3. return the partioned/transposed cleartext blocks with the lowest score
///    (most groundtruth-conforming character distribution)
fn minscore_transposed_cleartext_blocks(cyphertext: &[u8], keysizes: Vec<usize>) -> Vec<Vec<u8>> {
    keysizes
        .par_iter()
        .map(|keysize| partition(cyphertext, cyphertext.len() / keysize, *keysize))
        .map(transpose)
        .map(find_min_score_xor)
        .map(ScoredCleartextBlocks)
        .min()
        .unwrap_or(ScoredCleartextBlocks::empty())
        .into_blocks()
}

fn find_min_score_xor(transposed_cyphertext: Vec<Vec<u8>>) -> Vec<ScoredCleartext> {
    transposed_cyphertext
        .par_iter()
        .map(|block| xor_attack::find_min_score_xor(block))
        .collect()
}

/// guesses size of key used to encrypt text with repeating key xor by:
///
/// (1) enumerating a number of possible key sizes and for each one...
/// (2) measuring the edit distance (aka: "hamming distance", ie: number of differing bits)
///     between adjacent byte slices of this length in the cyphertext
/// (3) picking the keysizes that produced the 4 lowest edit distance
///     (ie: the blocks of bytes that are the most similar to one another)
fn guess_keysizes(cyphertext: &[u8]) -> Vec<usize> {
    // TODO: consider picking `num_hamming_dist_samples`
    // dynamically as a function of cyphertext length
    let mut keysize_distances = (MIN_KEYSIZE..MAX_KEYSIZE)
        .into_par_iter()
        .map(|keysize| calc_hamming_dist_for_keysize(cyphertext, keysize))
        .collect::<Vec<KeysizeDistance>>();
    keep_n_smallest(NUM_KEYSIZE_GUESSES, &mut keysize_distances)
        .par_iter()
        .map(|ksd| ksd.keysize)
        .collect()
}

/// partitions a byte array into `num_blocks` blocks of `block_size` size
fn partition(cyphertext: &[u8], num_blocks: usize, block_size: usize) -> Vec<&[u8]> {
    let num_blocks = truncate_num_blocks(cyphertext, num_blocks, block_size);
    (0..num_blocks)
        .into_par_iter()
        .map(|n| &cyphertext[(n * block_size)..((n + 1) * block_size)])
        .collect()
}

fn unpartition(blocks: Vec<Vec<u8>>) -> Vec<u8> {
    blocks.into_par_iter().flatten().collect()
}

/// truncate num blocks to closest multiple of `block_size` (to avoid indexing past end of cyphertext)
fn truncate_num_blocks(cyphertext: &[u8], num_blocks: usize, block_size: usize) -> usize {
    let blocks_len = num_blocks * block_size;
    match blocks_len < cyphertext.len() {
        true => num_blocks,
        false => num_blocks - (blocks_len % cyphertext.len()),
    }
}

/// transpose N `cyphertext_blocks` with length `keysize` into `keysize` blocks of length N
/// such that the ith block of the output consists of the ith element of every input block
fn transpose(blocks: Vec<&[u8]>) -> Vec<Vec<u8>> {
    // TODO: provide strong guarantee earlier that blocks will always have same length
    (0..blocks[0].len())
        .into_par_iter()
        .map(|idx| blocks.par_iter().map(|block| block[idx]).collect())
        .collect()
}

fn transpose_owned(blocks: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    transpose(blocks.par_iter().map(|bv| &bv[..]).collect())
}

fn calc_hamming_dist_for_keysize(cyphertext: &[u8], keysize: usize) -> KeysizeDistance {
    let blocks = partition(&cyphertext, NUM_HAMMING_DIST_SAMPLES, keysize);
    let dist = calc_avg_hamming_distance(&blocks);
    KeysizeDistance {
        keysize,
        dist: dist as f32 / keysize as f32, // normalize dist measurements based on keysize size
    }
}

fn calc_avg_hamming_distance(bss: &[&[u8]]) -> f32 {
    let dists = bss
        .par_iter()
        .enumerate()
        .map(|(idx, &bs)| calc_hamming_distances(bs, &bss[(idx + 1)..]))
        .flatten();
    let (sum, count) = (dists.clone().sum::<u32>(), dists.count());
    sum as f32 / count as f32
}

fn calc_hamming_distances(bs: &[u8], bss: &[&[u8]]) -> Vec<u32> {
    bss.par_iter()
        .map(|&_bs| calc_hamming_distance(bs, _bs))
        .collect()
}

/// measures number of differing bits in two byte arrays by
/// (1) xoring byte arrays, (2) counting number of set bits in xored byte array
/// (this works because xored byte array will have set bits in all positions
/// in which input byte arrays had differing bits)
fn calc_hamming_distance(bs1: &[u8], bs2: &[u8]) -> u32 {
    xor_cypher::xor(bs1, bs2)
        .par_iter()
        .map(|byte| byte.count_ones())
        .sum()
}

fn keep_n_smallest(n: usize, ksds: &mut Vec<KeysizeDistance>) -> Vec<KeysizeDistance> {
    ksds.sort_by(|a, b| a.dist.partial_cmp(&b.dist).unwrap());
    ksds.iter().take(n).cloned().collect()
}

#[cfg(test)]
mod xor_attack_repeating_tests {
    use super::*;
    use crate::encoding;

    lazy_static! {
        static ref KEY: Vec<u8> = b"foobarbazquxdoremi".to_vec();
        static ref CLEARTEXT: Vec<u8> =
            b"A screaming comes across the sky. It has happened before, \
              but there is nothing to compare it to now.\
              \n\
              It is too late. The Evacuation still proceeds, but it's all theatre. \
              There are no lights inside the cars. No light anywhere. \
              Above him lift girders old as an iron queen, \
              and glass somewhere far above that would let the light of day through. \
              But it's night. He's afraid of the way the glass will fall -- soon -- \
              it will be a spectacle: the fall of a crystal palace. \
              But coming down in total blackout, without one glint of light, \
              only great invisible crashing.\
              \n\
              Inside the carriage, which is built on several levels, \
              he sits in velveteen darkness, with nothing to smoke, \
              feeling metal nearer and farther rub and connect, steam escaping in puffs, \
              a vibration in the carriage's frame, a poising, an uneasiness, \
              all the others pressed in around, feeble ones, second sheep, \
              all out of luck and time: drunks, old veterans still in shock \
              from ordnance 20 years obsolete, hustlers in city clothes, derelicts, \
              exhausted women with more children than it seems could belong to anyone, \
              stacked about among the rest of the things to be carried out to salvation.\
              Only the nearer faces are visible at all, and at that only as half-silvered \
              images in a view finder, green-stained VIP faces remembered behind bulletproof \
              windows speeding through the c"//ity...
                .to_vec();
    }

    #[test]
    fn decrypting_repeating_key_xor_encrypted_cyphertext() {
        let cyphertext = xor_cypher::repeating_key_encrypt(&CLEARTEXT, &KEY);
        let decrypted = brute_force_decrypt(&cyphertext);
        assert_eq!(encoding::bytes2str(&CLEARTEXT), decrypted)
    }

    #[test]
    fn guessing_keysize() {
        // TODO: add keys with randomized lenghts/contents (quickcheck-style)
        // to increase confidence in values of NUM_KEYSIZE_GUESSES, NUM_HAMMING_DIST_SAMPLES
        let cyphertext = xor_cypher::repeating_key_encrypt(&CLEARTEXT, &KEY);
        let likely_keysizes = guess_keysizes(&cyphertext);

        assert!(likely_keysizes.contains(&KEY.len()));
    }

    // #[test]
    // fn finding_min_score_transposed_cleartext() {}

    #[test]
    fn transposing_borrowed_blocks() {
        assert_eq!(
            transpose(vec![&[1, 2, 3, 4], &[5, 6, 7, 8], &[9, 10, 11, 12]]),
            vec![
                vec![1, 5, 9],
                vec![2, 6, 10],
                vec![3, 7, 11],
                vec![4, 8, 12]
            ]
        )
    }

    #[test]
    fn transposing_owned_blocks() {
        assert_eq!(
            transpose_owned(vec![
                vec![1, 2, 3, 4],
                vec![5, 6, 7, 8],
                vec![9, 10, 11, 12]
            ]),
            vec![
                vec![1, 5, 9],
                vec![2, 6, 10],
                vec![3, 7, 11],
                vec![4, 8, 12]
            ]
        )
    }

    #[test]
    fn retransposing_blocks() {
        assert_eq!(
            transpose_owned(transpose(vec![
                &[1, 2, 3, 4],
                &[5, 6, 7, 8],
                &[9, 10, 11, 12]
            ])),
            vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8], vec![9, 10, 11, 12]]
        )
    }

    #[test]
    fn calculating_avg_hamming_distance() {
        let txts = &[
            &b"foobarbaz"[..],
            &b"fooooooo"[..],
            &b"baaaaaaar"[..],
            &b"bazzzzzzz"[..],
        ];

        assert_eq!(calc_avg_hamming_distance(txts), 20.0);
    }

    #[test]
    fn calculating_hamming_distance() {
        let txt1 = &b"this is a test"[..];
        let txt2 = &b"wokka wokka!!!"[..];

        assert_eq!(calc_hamming_distance(txt1, txt2), 37)
    }

    #[test]
    fn partitioning_cyphertext_into_blocks() {
        let cyphertext = [100, 101, 102, 103, 104, 105, 106];
        assert_eq!(partition(&cyphertext, 2, 2), vec![&[100, 101], &[102, 103]],);
    }

    #[test]
    fn partitioning_cyphertext_into_blocks_when_truncation_necessary() {
        let cyphertext = [1, 2, 3, 4, 5, 6, 7];
        assert_eq!(
            partition(&cyphertext, 4, 2),
            vec![&[1, 2], &[3, 4], &[5, 6]],
        );
    }

    #[test]
    fn calculating_number_of_blocks_to_partition_into() {
        assert_eq!(truncate_num_blocks(&[0; 7], 4, 2), 3);
        assert_eq!(truncate_num_blocks(&[0; 8], 4, 2), 4);
        assert_eq!(truncate_num_blocks(&[0; 8], 2, 2), 2);
    }

    #[test]
    fn keeping_n_smallest_hamming_distances() {
        let ksd1 = KeysizeDistance {
            dist: 1.0,
            keysize: 1,
        };

        let ksd2 = KeysizeDistance {
            dist: 2.0,
            keysize: 2,
        };

        let ksd3 = KeysizeDistance {
            dist: 3.0,
            keysize: 3,
        };

        let ksds = vec![ksd3.clone(), ksd2.clone(), ksd1.clone()];

        assert_eq!(keep_n_smallest(0, &mut ksds.clone()), vec![]);
        assert_eq!(keep_n_smallest(1, &mut ksds.clone()), vec![ksd1.clone()]);
        assert_eq!(
            keep_n_smallest(2, &mut ksds.clone()),
            vec![ksd1.clone(), ksd2.clone()]
        );
    }
}
