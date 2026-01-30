#[must_use]
pub fn is_valid(number: &str) -> bool {
    let digits: Vec<u32> = number
        .chars()
        .filter(char::is_ascii_digit)
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() < 13 || digits.len() > 16 {
        return false;
    }

    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            } else {
                d
            }
        })
        .sum();

    sum % 10 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_luhn_valid() {
        assert!(is_valid("4532015112830366"));
        assert!(is_valid("4532 0151 1283 0366"));
    }

    #[test]
    fn test_luhn_invalid() {
        assert!(!is_valid("4532015112830367"));
        assert!(!is_valid("1234567890123456"));
    }

    #[test]
    fn test_luhn_too_short() {
        assert!(!is_valid("123456789012"));
    }

    #[test]
    fn test_luhn_too_long() {
        assert!(!is_valid("12345678901234567"));
    }
}
