"""PrivilegeMap: the expected access rules for the Student Document Portal.

Each entry says "when <actor> requests <document>, the correct answer is ALLOW
or DENY". The IDOR scenario turns every entry into an executable test:

  * DENY entries are SECURITY tests. They fail if the app leaks the document.
  * ALLOW entries are REGRESSION tests. They fail if a "fix" blocks a user who
    is legitimately allowed in -- this is how over-restrictive patches get caught.
"""
from dataclasses import dataclass

ALLOW = "ALLOW"
DENY = "DENY"

# Document ids from fixtures/seed/student_portal.sql
DOC_ALICE_PRIVATE = 1
DOC_BOB_PRIVATE = 2
DOC_PUBLIC_ALGEBRA = 3


@dataclass(frozen=True)
class AccessRule:
    rule_id: str
    actor: str
    document_id: int
    expected: str
    reason: str


PRIVILEGE_MAP = [
    AccessRule("alice_reads_own_doc", "alice", DOC_ALICE_PRIVATE, ALLOW,
               "Students may read their own documents."),
    AccessRule("alice_reads_bob_doc", "alice", DOC_BOB_PRIVATE, DENY,
               "Students must not read another student's private document."),
    AccessRule("bob_reads_alice_doc", "bob", DOC_ALICE_PRIVATE, DENY,
               "Students must not read another student's private document."),
    AccessRule("teacher_reads_assigned_student_doc", "ms_rivera", DOC_ALICE_PRIVATE, ALLOW,
               "Teachers may read documents of students assigned to them."),
    AccessRule("teacher_reads_unassigned_student_doc", "mr_okafor", DOC_BOB_PRIVATE, DENY,
               "Teachers must not read documents of students not assigned to them."),
    AccessRule("anonymous_reads_private_doc", "anonymous", DOC_ALICE_PRIVATE, DENY,
               "Anonymous callers must not read private documents."),
    AccessRule("anonymous_reads_public_doc", "anonymous", DOC_PUBLIC_ALGEBRA, ALLOW,
               "Anyone may read public documents."),
]


def observed_decision(status_code):
    """Translate an HTTP status into ALLOW / DENY / None (None = unexpected, e.g. 500)."""
    if status_code == 200:
        return ALLOW
    if status_code in (401, 403, 404):
        return DENY
    return None
