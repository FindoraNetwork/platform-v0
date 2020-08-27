use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct SlidingSet<T> {
  current: usize,
  width: usize,
  map: Vec<Vec<T>>,
}

impl<T> SlidingSet<T> {
  pub fn new(width: usize) -> Self {
    let mut map = Vec::with_capacity(width as usize);
    for _ in 0..width {
      map.push(Vec::new());
    }
    let current = 0;
    SlidingSet { current,
                 width,
                 map }
  }

  pub fn incr_current(&mut self) {
    self.current += 1;
    let current_index = self.current % self.width;
    self.map[current_index].clear();
  }
}

impl<T: Eq + Copy + std::fmt::Debug> SlidingSet<T> {
  pub fn contains_key(&self, key: T) -> bool {
    self.get(key).is_some()
  }

  pub fn has_key_at(&self, key: T, index: usize) -> bool {
    if index > self.current || index + self.width < (self.current + 1) {
      false
    } else {
      self.map[index % self.width].contains(&key)
    }
  }

  pub fn get(&self, key: T) -> Option<usize> {
    for (index, vec) in self.map.iter().enumerate() {
      for k in vec.iter() {
        if *k == key {
          let offset = self.current / self.width;
          return Some(offset + index);
        }
      }
    }
    None
  }

  pub fn insert(&mut self, key: T, index: usize) -> Result<(), String> {
    if index <= self.current && index + self.width >= (self.current + 1) {
      if self.map[index % self.width].contains(&key) {
        Err(format!("SlidingSet::insert: ({:?}, {}) already in set", key, index))
      } else {
        self.map[index % self.width].push(key);
        Ok(())
      }
    } else {
      Err(format!("({:?}, {}) is out of range", key, index))
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use cryptohash::sha256::{hash, Digest};
  use rand::distributions::Alphanumeric;
  use rand::{thread_rng, Rng};

  //
  #[test]
  fn test_basic() {
    let factor = 3;
    let width: usize = 4;
    let mut ss = SlidingSet::<Digest>::new(width);
    let mut names = Vec::new();
    for _ in 0..width * factor {
      let rand_string: String = thread_rng().sample_iter(&Alphanumeric).take(16).collect();
      names.push(rand_string);
    }
    let digests: Vec<Digest> = names.iter()
                                    .map(|s| hash(&bincode::serialize(&s).unwrap()))
                                    .collect();

    // test the "sliding property".
    let mut n = 0;
    for i in 0..factor {
      for _ in 0..width {
        ss.insert(digests[n], n);
        assert!(ss.contains_key(digests[n]));
        ss.incr_current();
        n += 1;
      }
      assert!(!ss.contains_key(digests[i * width]));
      assert!(ss.contains_key(digests[(i + 1) * width - 1]));
    }
  }
}
