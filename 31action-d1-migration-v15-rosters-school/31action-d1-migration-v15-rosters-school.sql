CREATE TABLE IF NOT EXISTS rosters (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  school TEXT,
  team TEXT,
  sport TEXT,
  season TEXT,
  notes TEXT,
  status TEXT NOT NULL DEFAULT 'active'
    CHECK(status IN ('active','archived')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rosters_school
ON rosters(school);

CREATE INDEX IF NOT EXISTS idx_rosters_team_sport
ON rosters(team,sport);

CREATE INDEX IF NOT EXISTS idx_rosters_status
ON rosters(status,updated_at);

CREATE TABLE IF NOT EXISTS roster_players (
  id TEXT PRIMARY KEY,
  roster_id TEXT NOT NULL,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  display_name TEXT NOT NULL,
  normalized_name TEXT NOT NULL,
  jersey_number TEXT,
  school TEXT,
  team TEXT,
  sport TEXT,
  season TEXT,
  athlete_id TEXT,
  notes TEXT,
  status TEXT NOT NULL DEFAULT 'active'
    CHECK(status IN ('active','inactive')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(roster_id) REFERENCES rosters(id) ON DELETE CASCADE,
  FOREIGN KEY(athlete_id) REFERENCES athlete_profiles(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_roster_players_roster
ON roster_players(roster_id,status);

CREATE INDEX IF NOT EXISTS idx_roster_players_name
ON roster_players(normalized_name,status);

CREATE INDEX IF NOT EXISTS idx_roster_players_jersey
ON roster_players(jersey_number,status);

CREATE INDEX IF NOT EXISTS idx_roster_players_school
ON roster_players(school,status);

CREATE INDEX IF NOT EXISTS idx_roster_players_team_sport
ON roster_players(team,sport,status);

CREATE TABLE IF NOT EXISTS gallery_rosters (
  gallery_id TEXT NOT NULL,
  roster_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(gallery_id,roster_id),
  FOREIGN KEY(gallery_id) REFERENCES galleries(id) ON DELETE CASCADE,
  FOREIGN KEY(roster_id) REFERENCES rosters(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_gallery_rosters_roster
ON gallery_rosters(roster_id,gallery_id);

CREATE TABLE IF NOT EXISTS player_tag_suggestions (
  id TEXT PRIMARY KEY,
  photo_id TEXT NOT NULL,
  gallery_id TEXT NOT NULL,
  roster_player_id TEXT,
  suggested_name TEXT NOT NULL,
  suggested_jersey_number TEXT,
  suggested_school TEXT,
  suggested_team TEXT,
  suggested_sport TEXT,
  normalized_name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK(status IN ('pending','approved','rejected')),
  submitted_by_user_id TEXT,
  approved_athlete_id TEXT,
  submitted_at TEXT NOT NULL,
  reviewed_at TEXT,
  reviewed_by TEXT,
  FOREIGN KEY(photo_id) REFERENCES photos(id) ON DELETE CASCADE,
  FOREIGN KEY(gallery_id) REFERENCES galleries(id) ON DELETE CASCADE,
  FOREIGN KEY(roster_player_id) REFERENCES roster_players(id) ON DELETE SET NULL,
  FOREIGN KEY(submitted_by_user_id) REFERENCES user_accounts(id) ON DELETE SET NULL,
  FOREIGN KEY(approved_athlete_id) REFERENCES athlete_profiles(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_player_tag_suggestions_gallery
ON player_tag_suggestions(gallery_id,status,submitted_at);

CREATE INDEX IF NOT EXISTS idx_player_tag_suggestions_photo
ON player_tag_suggestions(photo_id,status);

CREATE INDEX IF NOT EXISTS idx_player_tag_suggestions_name
ON player_tag_suggestions(normalized_name,status);

CREATE INDEX IF NOT EXISTS idx_player_tag_suggestions_roster_player
ON player_tag_suggestions(roster_player_id,status);