#[macro_export]
macro_rules! declare_upgrade {
    ($from:ident, $to:ident) => {
        pub trait Upgrade {
            type To;
            fn upgrade(self) -> Self::To;
        }

        impl<T> Upgrade for Vec<T>
        where
            T: Upgrade,
        {
            type To = Vec<T::To>;
            fn upgrade(self) -> Self::To {
                self.into_iter().map(|v| v.upgrade()).collect()
            }
        }

        impl<K, V> Upgrade for BTreeMap<K, V>
        where
            K: Upgrade,
            V: Upgrade,
            K::To: Ord + std::hash::Hash,
        {
            type To = BTreeMap<K::To, V::To>;
            fn upgrade(self) -> Self::To {
                self.into_iter()
                    .map(|(k, v)| (k.upgrade(), v.upgrade()))
                    .collect()
            }
        }

        impl<T> Upgrade for Box<T>
        where
            T: Upgrade,
        {
            type To = Box<T::To>;
            fn upgrade(self) -> Self::To {
                Box::new((*self).upgrade())
            }
        }

        impl<T> Upgrade for Option<T>
        where
            T: Upgrade,
        {
            type To = Option<T::To>;
            fn upgrade(self) -> Self::To {
                self.map(Upgrade::upgrade)
            }
        }

        //trivial_upgrade!(bool);
        //trivial_upgrade!(u32);
        //trivial_upgrade!(u64);
        //trivial_upgrade!(u128);
        //trivial_upgrade!(String);
        //trivial_upgrade!(Duration);
    };
}

#[macro_export]
macro_rules! impl_upgrade {
    ($($seg:ident)::*; $fun:expr) => {
        impl_upgrade!{
            $($seg)::*;
            $($seg)::*;
            $fun
        }
    };
    ($($from_seg:ident)::*; $($to_seg:ident)::*; $fun:expr) => {
        impl Upgrade for from::$($from_seg)::* {
            #[allow(unused)]
            type To = to::$($to_seg)::*;
            fn upgrade(self) -> Self::To {
                type From = from::$($from_seg)::*;
                type To = to::$($to_seg)::*;
                $fun(self)
            }
        }
    };
}

#[macro_export]
macro_rules! forward_enum_upgrade {
    ($($seg:ident)::*; $($var:ident),*) => {
        forward_enum_upgrade! {
            $($seg)::*;
            $($seg)::*;
            $($var),*
        }
    };
    ($($from_seg:ident)::*; $($to_seg:ident)::*; $($var:ident),*) => {
        impl Upgrade for from::$($from_seg)::* {
            type To = to::$($to_seg)::*;
            fn upgrade(self) -> Self::To {
                match self {
                    $(
                        Self::$var(v) => Self::To::$var(v.upgrade())
                    ),*
                }
            }
        }
    };
}

#[macro_export]
macro_rules! forward_struct_upgrade {
    ($($seg:ident)::*; $($field:ident),*) => {
        forward_struct_upgrade! {
            $($seg)::*;
            $($seg)::*;
            $($field),*
        }
    };
    ($($from_seg:ident)::*; $($to_seg:ident)::*; $($field:ident),*) => {
        impl Upgrade for from::$($from_seg)::* {
            type To = to::$($to_seg)::*;
            fn upgrade(self) -> Self::To {
                Self::To {
                    $(
                      $field: self.$field.upgrade()
                    ),*
                }
            }
        }
    };
}

#[macro_export]
macro_rules! forward_upgrade {
    (enum $($seg:ident)::*; $($var:ident),*) => {
      iroha_squash_macros::forward_enum_upgrade!($($seg)::*; $($var),*);
    };
    (struct $($seg:ident)::*; $($field:ident),*) => {
      iroha_squash_macros::forward_struct_upgrade!($($seg)::*; $($field),*);
    };
}

#[macro_export]
macro_rules! trivial_upgrade {
    ($typ:ty) => {
        impl Upgrade for $typ {
            type To = $typ;
            fn upgrade(self) -> Self::To {
                self
            }
        }
    };
}

#[macro_export]
macro_rules! trivial_enum_upgrade {
    ($($seg:ident)::*; $($var:ident),*) => {
        trivial_enum_upgrade! {
            $($seg)::*;
            $($seg)::*;
            $($var),*
        }
    };
    ($($from_seg:ident)::*; $($to_seg:ident)::*; $($var:ident),*) => {
        impl Upgrade for from::$($from_seg)::* {
            type To = to::$($to_seg)::*;

            fn upgrade(self) -> Self::To {
                match self {
                    $(
                      Self::$var => Self::To::$var
                    ),*
                }
            }
        }
    };
}
