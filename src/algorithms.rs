use num_bigint::RandBigInt;
use num_bigint::{prime::probably_prime, BigUint, RandPrime};
use num_integer::Integer;
use num_traits::One;
use rand_core::{CryptoRng, RngCore};

use num_iter::range;

use crate::ElgamalGroup;
use crate::keys::ElgamalGroupElements;

pub(crate) fn generate_prime<R: RngCore + CryptoRng>(rng: &mut R, bit_size: usize) -> BigUint {
    rng.gen_prime(bit_size)
}

// pub fn elgamal_parameter_generation_type1<R: RngCore + CryptoRng>(rng: &mut R, l: usize, k: usize) -> (BigUint, BigUint, BigUint){
//     'central: loop {
//         let q = generate_prime(rng, k);

//         println!("generate q: {:?}", q);

//         let maximum_tries = (2 as f64).powf((l as f64).log(2_f64) + 2_f64) as usize;
//         let module = &q + &q;
//         let mut count = 0;
//         let p: BigUint = loop {

//             let mut p = rng.gen_biguint(l);
//             println!("generate try p: {:?}", p);
//             println!("module: {:?}", module);

//             println!("sub p: {:?}", &p.mod_floor(&module));

//             p -= &p.mod_floor(&module) - BigUint::one();
//             println!("generate try p updated: {:?}", p);

//             if p.bits() == l && probably_prime(&p, 10)  {
//                 println!("break p: {:?}", p);
//                 break p;
//             } else {
//                 if count > maximum_tries {
//                     continue 'central;
//                 }
//                 count += 1;
//             }
//         };
//         println!("generate p: {:?}", p);

//         let exponent = (&p - BigUint::one()) / &q;
//         for h in range::<BigUint>(BigUint::one() + BigUint::one(), &p - BigUint::one())
//         {
//             println!("generated h: {}", h);
//             let g = h.modpow(&exponent, &p);
//             println!("generated g: {}", g);

//             if (&g + BigUint::one()).is_multiple_of(&p) == false && (&g - BigUint::one()).is_multiple_of(&p) == false
//             {
//                 return (q, p, g)
//             }
//         }
//         println!("failed");
//     }
// }

pub(crate) fn elgamal_parameter_generation_type1<R: RngCore + CryptoRng>(
    rng: &mut R,
    l: usize,
    k: usize,
) -> (BigUint, BigUint, BigUint) {
    'central: loop {
        let q = generate_prime(rng, k);

        let maximum_tries = 2_f64.powf((l as f64).log(2_f64) + 2_f64) as usize;
        let module = &q + &q;
        let mut count = 0;
        let p: BigUint = loop {
            let mut p = rng.gen_biguint(l);

            p -= &p.mod_floor(&module);
            p += BigUint::one();

            if p.bits() == l && probably_prime(&p, 10) {
                break p;
            } else {
                if count > maximum_tries {
                    continue 'central;
                }
                count += 1;
            }
        };

        let exponent = (&p - BigUint::one()) / &q;
        for h in range::<BigUint>(BigUint::one() + BigUint::one(), &p - BigUint::one()) {
            let g = h.modpow(&exponent, &p);

            if !(&g + BigUint::one()).is_multiple_of(&p)
                && !(&g - BigUint::one()).is_multiple_of(&p)
            {
                return (q, p, g);
            }
        }
    }
}

pub fn key_generation<R: RngCore + CryptoRng>(
    rng: &mut R,
    group: &ElgamalGroup,
) -> (BigUint, BigUint) {
    let x = rng.gen_biguint_range(&BigUint::one(), group.get_q());

    (group.get_g().modpow(&x, group.get_p()), x)
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn elgamal_gen_1() {
        let mut rng = StdRng::from_entropy();

        let (_q, _p, _g) = elgamal_parameter_generation_type1(&mut rng, 5, 3);
    }
}
