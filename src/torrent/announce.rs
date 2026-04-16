use rand::seq::SliceRandom;

/// implements a BEP-0012 announce-list protocol extension
pub trait AnnounceSource {
    fn next(&mut self) -> Option<url::Url>;
    fn on_success(&mut self);
}

pub struct SingleAnnounce {
    url: url::Url,
    done: bool,
}

impl SingleAnnounce {
    pub fn new(url: url::Url) -> Self {
        Self { url, done: false }
    }
}

impl AnnounceSource for SingleAnnounce {
    fn next(&mut self) -> Option<url::Url> {
        if self.done {
            None
        } else {
            self.done = true;
            Some(self.url.clone())
        }
    }

    fn on_success(&mut self) {}
}

pub struct AnnounceSession<'a> {
    list: &'a mut AnnounceList,
    tier_idx: usize,
    tracker_idx: usize,
    last: Option<(usize, usize)>,
}

impl<'a> AnnounceSession<'a> {
    fn new(list: &'a mut AnnounceList) -> Self {
        Self {
            list,
            tier_idx: 0,
            tracker_idx: 0,
            last: None,
        }
    }
}

impl<'a> AnnounceSource for AnnounceSession<'a> {
    fn next(&mut self) -> Option<url::Url> {
        while self.tier_idx < self.list.tiers.len() {
            let tier = &self.list.tiers[self.tier_idx];
            if self.tracker_idx < tier.trackers.len() {
                let idx = self.tracker_idx;
                self.tracker_idx += 1;
                self.last = Some((self.tier_idx, idx));
                return Some(tier.trackers[idx].clone());
            }
            self.tier_idx += 1;
            self.tracker_idx = 0;
        }
        None
    }

    fn on_success(&mut self) {
        if let Some((tier_idx, tracker_idx)) = self.last.take() {
            let tier = &mut self.list.tiers[tier_idx];
            let tracker = tier.trackers.remove(tracker_idx);
            tier.trackers.insert(0, tracker);
        }
    }
}

pub struct Announce {
    announce_list: Option<AnnounceList>,
    announce: url::Url,
}

struct AnnounceList {
    tiers: Vec<Tier>,
}

struct Tier {
    trackers: Vec<url::Url>,
}

impl Announce {
    pub fn new(announce_list: Option<Vec<Vec<url::Url>>>, announce: url::Url) -> Self {
        let announce_list = announce_list.map(|tiers| {
            let mut rng = rand::rng();

            let tiers = tiers
                .into_iter()
                .map(|mut trackers| {
                    trackers.shuffle(&mut rng);
                    Tier { trackers }
                })
                .collect();

            AnnounceList { tiers }
        });
        Self {
            announce_list,
            announce,
        }
    }

    pub fn session(&mut self) -> Box<dyn AnnounceSource + '_> {
        if let Some(list) = &mut self.announce_list {
            Box::new(AnnounceSession::new(list))
        } else {
            Box::new(SingleAnnounce::new(self.announce.clone()))
        }
    }
}
