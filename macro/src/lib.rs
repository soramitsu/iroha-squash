#[macro_export]
macro_rules! map_values {
    ($map:expr) => {
        $map.par_iter().map(|ref_multi| ref_multi.value().clone())
    };
}

#[macro_export]
macro_rules! iter_values {
    ($map:expr) => {
        $map.cloned().collect::<Vec<_>>().into_par_iter()
    };
}

#[macro_export]
macro_rules! prelude {
    () => {
        use iroha_data_model::prelude::*;
        use rayon::prelude::*;
    };
}

#[macro_export]
macro_rules! register {
    ($iter:expr) => {
        ($iter).map(RegisterBox::new).map(Instruction::Register)
    };
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("I/O Error: {0}")]
    Io(#[from] std::io::Error),
}
