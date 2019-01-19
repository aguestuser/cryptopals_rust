use std::collections::HashMap;

pub const CHARACTER_BYTES: [u8; 99] = [
    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
    56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
    80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102,
    103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121,
    122, 123, 124, 125, 126, 228, 230, 246, 252,
];

lazy_static! {
    // source: https://reusablesec.blogspot.com/2009/05/character-frequency-analysis-info.html
    pub static ref FREQS_BY_CHAR: HashMap<u8, f64> = {
        let mut m = HashMap::<u8, f64>::new();
        m.insert('\'' as u8, 1.22045e-06);
        m.insert(' ' as u8, 0.166666);
        m.insert('!' as u8, 0.000306942);
        m.insert('\\' as u8, 1.83067e-06);
        m.insert('#' as u8, 8.54313e-05);
        m.insert('$' as u8, 9.70255e-05);
        m.insert('%' as u8, 1.70863e-05);
        m.insert('&' as u8, 1.34249e-05);
        m.insert('(' as u8, 4.27156e-06);
        m.insert(')' as u8, 1.15942e-05);
        m.insert('*' as u8, 0.000241648);
        m.insert('+' as u8, 2.31885e-05);
        m.insert(',' as u8, 3.23418e-05);
        m.insert('-' as u8, 0.000197712);
        m.insert('.' as u8, 0.000316706);
        m.insert('/' as u8, 3.11214e-05);
        m.insert('0' as u8, 0.0274381);
        m.insert('1' as u8, 0.0435053);
        m.insert('2' as u8, 0.0312312);
        m.insert('3' as u8, 0.0243339);
        m.insert('4' as u8, 0.0194265);
        m.insert('5' as u8, 0.0188577);
        m.insert('6' as u8, 0.0175647);
        m.insert('7' as u8, 0.01621);
        m.insert('8' as u8, 0.0166225);
        m.insert('9' as u8, 0.0179558);
        m.insert(':' as u8, 5.49201e-06);
        m.insert(';' as u8, 2.07476e-05);
        m.insert('<' as u8, 4.27156e-06);
        m.insert('=' as u8, 1.40351e-05);
        m.insert('>' as u8, 1.83067e-06);
        m.insert('?' as u8, 2.07476e-05);
        m.insert('@' as u8, 0.000238597);
        m.insert('A' as u8, 0.00130466);
        m.insert('B' as u8, 0.000806715);
        m.insert('C' as u8, 0.000660872);
        m.insert('D' as u8, 0.000698096);
        m.insert('E' as u8, 0.000970865);
        m.insert('F' as u8, 0.000417393);
        m.insert('G' as u8, 0.000497332);
        m.insert('H' as u8, 0.000544319);
        m.insert('I' as u8, 0.00070908);
        m.insert('J' as u8, 0.000363083);
        m.insert('K' as u8, 0.000460719);
        m.insert('L' as u8, 0.000775594);
        m.insert('M' as u8, 0.000782306);
        m.insert('N' as u8, 0.000748134);
        m.insert('O' as u8, 0.000729217);
        m.insert('P' as u8, 0.00073715);
        m.insert('Q' as u8, 0.000147064);
        m.insert('R' as u8, 0.0008476);
        m.insert('S' as u8, 0.00108132);
        m.insert('T' as u8, 0.000801223);
        m.insert('U' as u8, 0.000350268);
        m.insert('V' as u8, 0.000235546);
        m.insert('W' as u8, 0.000320367);
        m.insert('X' as u8, 0.000142182);
        m.insert('Y' as u8, 0.000255073);
        m.insert('Z' as u8, 0.000170252);
        m.insert('[' as u8, 1.0984e-05);
        m.insert('\\' as u8, 1.15942e-05);
        m.insert(']' as u8, 1.0984e-05);
        m.insert('^' as u8, 1.95272e-05);
        m.insert('_' as u8, 0.000122655);
        m.insert('`' as u8, 1.15942e-05);
        m.insert('a' as u8, 0.0752766);
        m.insert('b' as u8, 0.0229145);
        m.insert('c' as u8, 0.0257276);
        m.insert('d' as u8, 0.0276401);
        m.insert('e' as u8, 0.070925);
        m.insert('f' as u8, 0.012476);
        m.insert('g' as u8, 0.0185331);
        m.insert('h' as u8, 0.0241319);
        m.insert('i' as u8, 0.0469732);
        m.insert('j' as u8, 0.00836677);
        m.insert('k' as u8, 0.0196828);
        m.insert('l' as u8, 0.0377728);
        m.insert('m' as u8, 0.0299913);
        m.insert('n' as u8, 0.0456899);
        m.insert('o' as u8, 0.0517);
        m.insert('p' as u8, 0.0245578);
        m.insert('q' as u8, 0.00346119);
        m.insert('r' as u8, 0.0496032);
        m.insert('s' as u8, 0.0461079);
        m.insert('t' as u8, 0.0387388);
        m.insert('u' as u8, 0.0210191);
        m.insert('v' as u8, 0.00833626);
        m.insert('w' as u8, 0.0124492);
        m.insert('x' as u8, 0.00573305);
        m.insert('y' as u8, 0.0152483);
        m.insert('z' as u8, 0.00632558);
        m.insert('{' as u8, 1.22045e-06);
        m.insert('|' as u8, 1.22045e-06);
        m.insert('}' as u8, 0.0610223);
        m.insert('~' as u8, 1.52556e-05);
        m.insert('ä' as u8, 6.10223e-07);
        m.insert('æ' as u8, 1.83067e-06);
        m.insert('ö' as u8, 6.10223e-07);
        m.insert('ü' as u8, 1.22045e-06);
        m
    };
}

// according to above frequency distributions
pub const SUMMED_SQUARED_FREQUENCIES: f64 = 0.0687832;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_char_lookup() {
        assert_eq!(FREQS_BY_CHAR.get(&('a' as u8)), Some(&0.0752766))
    }

    #[test]

    fn test_byte_lookup() {
        assert_eq!(FREQS_BY_CHAR.get(&97), Some(&0.0752766))
    }
}
