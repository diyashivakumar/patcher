-- Synthetic data for the Student Document Portal practice app.
-- Every name, token and document below is fictional. Never put real data here.
-- The test harness loads this into a fresh, throwaway SQLite file for every run.

CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK (role IN ('student', 'teacher')),
    api_token TEXT NOT NULL UNIQUE
);

CREATE TABLE documents (
    id INTEGER PRIMARY KEY,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    is_public INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE teacher_students (
    teacher_id INTEGER NOT NULL REFERENCES users(id),
    student_id INTEGER NOT NULL REFERENCES users(id),
    PRIMARY KEY (teacher_id, student_id)
);

INSERT INTO users (id, username, role, api_token) VALUES
    (1, 'alice',     'student', 'tok-alice-SYNTHETIC'),
    (2, 'bob',       'student', 'tok-bob-SYNTHETIC'),
    (3, 'ms_rivera', 'teacher', 'tok-rivera-SYNTHETIC'),
    (4, 'mr_okafor', 'teacher', 'tok-okafor-SYNTHETIC'),
    (5, 'carol',     'student', 'tok-carol-SYNTHETIC');

-- ms_rivera teaches alice only. mr_okafor teaches nobody in this dataset.
INSERT INTO teacher_students (teacher_id, student_id) VALUES (3, 1);

INSERT INTO documents (id, owner_id, title, body, is_public) VALUES
    (1, 1, 'Alice Private Diary',      'SYNTHETIC-PRIVATE-ALICE: notes for my eyes only', 0),
    (2, 2, 'Bob Private Grades',       'SYNTHETIC-PRIVATE-BOB: term grades draft',        0),
    (3, 3, 'Algebra Notes',            'Public algebra notes for all students',          1),
    (4, 3, 'Chemistry Lab Safety',     'Public lab safety rules',                        1),
    (5, 4, 'O''Brien Reading List',    'Public reading list (title contains a quote)',   1);

-- Data Exposure Forensics canary records (testing/canaries.py is the registry).
-- Every field carries its own marker, so response inspection can prove WHICH fields
-- of WHICH record were returned. Fabricated values only. All private (is_public = 0),
-- so they never appear in legitimate public searches.
INSERT INTO documents (id, owner_id, title, body, is_public) VALUES
    (101, 1, 'Counselling Record [CANARY-STUDENT-A-101:TITLE]', 'Fabricated counselling notes [CANARY-STUDENT-A-101:BODY]', 0),
    (202, 2, 'Counselling Record [CANARY-STUDENT-B-202:TITLE]', 'Fabricated counselling notes [CANARY-STUDENT-B-202:BODY]', 0),
    (303, 5, 'Counselling Record [CANARY-STUDENT-C-303:TITLE]', 'Fabricated counselling notes [CANARY-STUDENT-C-303:BODY]', 0);
