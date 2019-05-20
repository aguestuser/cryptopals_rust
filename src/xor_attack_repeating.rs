use crate::xor_cypher;
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelIterator,
};

const NUM_KEYSIZE_GUESSES: usize = 4;
const NUM_HAMMING_DIST_SAMPLES: usize = 20;

#[derive(Clone, PartialEq, Debug)]
struct KeysizeDistance {
    keysize: usize,
    dist: f32,
}

///
/// guesses size of key used to encrypt text with repeating key xor by:
///
/// (1) enumerating a number of possible key sizes and for each one...
/// (2) measuring the hamming distance (number of differing bits)
///     between adjacent byte slices of this length in the cyphertext
/// (3) picking the keysize that produced the lowest hamming distance
///     (ie: the blocks of bytes that are the most similar to one another)
///
/// TODO: figure out why this is a good heuristic
///
fn guess_keysizes(cyphertext: &[u8]) -> Vec<usize> {
    // TODO: consider picking `num_hamming_dist_samples`
    // dynamically as a function of cyphertext length
    let mut keysize_distances = (2usize..40usize)
        .into_par_iter()
        .map(|keysize| calc_hamming_dist_for_keysize(cyphertext, keysize))
        .collect::<Vec<KeysizeDistance>>();
    keep_n_smallest(NUM_KEYSIZE_GUESSES, &mut keysize_distances)
        .par_iter()
        .map(|ksd| ksd.keysize)
        .collect()
}

fn partition_into_blocks(cyphertext: &[u8], num_blocks: usize, block_size: usize) -> Vec<&[u8]> {
    // TODO: pad or truncate cyphertext to closest multiple of `block_size`
    // to avoid trying to index into it past its end
    (0..num_blocks)
        .into_par_iter()
        .map(|n| &cyphertext[(n * block_size)..((n + 1) * block_size)])
        .collect::<Vec<&[u8]>>()
}

fn calc_hamming_dist_for_keysize(cyphertext: &[u8], keysize: usize) -> KeysizeDistance {
    let blocks = partition_into_blocks(&cyphertext, NUM_HAMMING_DIST_SAMPLES, keysize);
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

///
/// measures number of differing bits in two byte arrays by:
///
/// (1) xoring byte arrays
/// (2) counting number of set bits in xored byte array
///
/// this workeysize because xored byte array will have set bits in all positions
/// in which input byte arrays had differing bits)
///
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

    #[test]
    fn guessing_keysize() {
        let cleartext = b"A screaming comes across the sky. It has happened before, \
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
                          windows speeding through the city...".to_vec();

        // TODO: add keys with randomized lenghts/contents (quickcheck-style)
        // to increase confidence in values of NUM_KEYSIZE_GUESSES, NUM_HAMMING_DIST_SAMPLES
        let key = b"foobarbazlala".to_vec();
        let cyphertext = xor_cypher::repeating_key_encrypt(&cleartext, &key);
        let likely_keysizes = guess_keysizes(&cyphertext);

        assert!(likely_keysizes.contains(&key.len()));
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
        assert_eq!(
            partition_into_blocks(&cyphertext, 2, 2),
            vec![&[100, 101], &[102, 103]],
        );
        // TODO: make this test true: will prevent panicks resulting from
        // attempting to index into cyphertext byte slice past its end
        // assert_eq!(
        //     partition_into_blocks(&cyphertext, 4, 2),
        //     vec![&[100, 101, 102, 103]],
        // );
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
