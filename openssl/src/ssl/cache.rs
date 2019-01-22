use linked_hash_set::LinkedHashSet;
use ssl::{SslSession, SslSessionRef};
use std::borrow::Borrow;
use std::collections::hash_map::{Entry, HashMap};
use std::hash::{Hash, Hasher};

#[derive(Hash, PartialEq, Eq, Clone)]
pub struct SessionKey {
    pub host: String,
    pub port: u16,
}

#[derive(Clone)]
struct HashSession(SslSession);

impl PartialEq for HashSession {
    fn eq(&self, other: &HashSession) -> bool {
        self.0.id() == other.0.id()
    }
}

impl Eq for HashSession {}

impl Hash for HashSession {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        self.0.id().hash(state);
    }
}

impl Borrow<[u8]> for HashSession {
    fn borrow(&self) -> &[u8] {
        self.0.id()
    }
}

pub struct SessionCache {
    sessions: HashMap<SessionKey, LinkedHashSet<HashSession>>,
    reverse: HashMap<HashSession, SessionKey>,
}

impl SessionCache {
    pub fn new() -> SessionCache {
        SessionCache {
            sessions: HashMap::new(),
            reverse: HashMap::new(),
        }
    }

    pub fn insert(&mut self, key: SessionKey, session: SslSession) {
        let session = HashSession(session);

        self.sessions
            .entry(key.clone())
            .or_insert_with(LinkedHashSet::new)
            .insert(session.clone());
        self.reverse.insert(session.clone(), key);
    }

    pub fn get(&mut self, key: &SessionKey) -> Option<SslSession> {
        let sessions = self.sessions.get_mut(key)?;
        let session = sessions.front().cloned()?;
        sessions.refresh(&session);
        Some(session.0)
    }

    pub fn remove(&mut self, session: &SslSessionRef) {
        let key = match self.reverse.remove(session.id()) {
            Some(key) => key,
            None => return,
        };

        if let Entry::Occupied(mut sessions) = self.sessions.entry(key) {
            sessions.get_mut().remove(session.id());
            if sessions.get().is_empty() {
                sessions.remove();
            }
        }
    }
}
