from __future__ import annotations

import math
from pathlib import Path

from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs/locus-memory-visual-guide.pdf'
OUT.parent.mkdir(parents=True, exist_ok=True)
FONT = Path('/System/Library/Fonts/Supplemental')
pdfmetrics.registerFont(TTFont('Body', str(FONT / 'Arial.ttf')))
pdfmetrics.registerFont(TTFont('Bold', str(FONT / 'Arial Bold.ttf')))
pdfmetrics.registerFont(TTFont('Mono', str(FONT / 'Andale Mono.ttf')))
pdfmetrics.registerFontFamily('Body', normal='Body', bold='Bold', italic='Body', boldItalic='Bold')

W, H = 864, 576
BG = '#F6F4EF'
INK = '#182E38'
MUTED = '#53676F'
LINE = '#D4DEDD'
TEAL = '#087F76'
PALE_TEAL = '#E3F1EB'
BLUE = '#355CB4'
PALE_BLUE = '#E9EFFB'
AMBER = '#9C641E'
PALE_AMBER = '#FAEED9'
WHITE = '#FFFFFF'
GREY = '#EDF0EE'
RED = '#A14A42'
BASE = 'https://github.com/nahid-sparktales/locus-memory/blob/main/'
REPO = 'https://github.com/nahid-sparktales/locus-memory'
c = canvas.Canvas(str(OUT), pagesize=(W, H), pageCompression=1)
c.setTitle('Locus Memory | A visual guide to the engine and its parts')
c.setAuthor('Locus')
c.setSubject('Locus Memory 0.3.0 working-tree architecture; validation and release deferred')


def rect(x, y, w, h, fill=WHITE, stroke=None, radius=12):
    c.setFillColor(HexColor(fill))
    c.setStrokeColor(HexColor(stroke or fill))
    c.setLineWidth(0.8)
    c.roundRect(x, H-y-h, w, h, radius, stroke=bool(stroke), fill=1)


def text(value, x, y, size=12, color=INK, font='Body', align='left'):
    c.setFillColor(HexColor(color))
    c.setFont(font, size)
    f = {'left': c.drawString, 'center': c.drawCentredString, 'right': c.drawRightString}[align]
    f(x, H-y-size, value)


def para(value, x, y, w, size=12, color=INK, leading=None, max_h=None, font='Body'):
    style = ParagraphStyle('p', fontName=font, fontSize=size, leading=leading or size*1.32,
                           textColor=HexColor(color), spaceAfter=0)
    p = Paragraph(value, style)
    _, h = p.wrap(w, H)
    if max_h is not None and h > max_h + .1:
        raise ValueError(f'Text overflow {h:.1f} > {max_h}: {value}')
    p.drawOn(c, x, H-y-h)
    return h


def line(x1, y1, x2, y2, color=LINE, width=1.2, dash=None):
    c.saveState()
    c.setStrokeColor(HexColor(color))
    c.setLineWidth(width)
    if dash:
        c.setDash(*dash)
    c.line(x1, H-y1, x2, H-y2)
    c.restoreState()


def arrow(points, color=TEAL, width=1.8, both=False):
    for (x1, y1), (x2, y2) in zip(points, points[1:]):
        line(x1, y1, x2, y2, color, width)
    def head(a, b):
        angle = math.atan2(b[1]-a[1], b[0]-a[0])
        p = c.beginPath()
        p.moveTo(b[0], H-b[1])
        for d in (-.48, .48):
            p.lineTo(b[0]-7*math.cos(angle+d), H-(b[1]-7*math.sin(angle+d)))
        p.close()
        c.setFillColor(HexColor(color))
        c.drawPath(p, fill=1, stroke=0)
    head(points[-2], points[-1])
    if both:
        head(points[1], points[0])


def pill(label, x, y, color=TEAL, fill=PALE_TEAL, width=None):
    width = width or pdfmetrics.stringWidth(label, 'Bold', 9) + 18
    rect(x, y, width, 21, fill, radius=10)
    text(label, x+9, y+4, 9, color, 'Bold')
    return width


def dot(number, x, y, color=TEAL):
    c.setFillColor(HexColor(color))
    c.circle(x+11, H-y-11, 11, stroke=0, fill=1)
    text(str(number), x+11, y+4, 11, WHITE, 'Bold', 'center')


def link(label, url, x, y, size=9.2, color=MUTED):
    text(label, x, y, size, color)
    w = pdfmetrics.stringWidth(label, 'Body', size)
    c.linkURL(url, (x, H-y-size-2, x+w, H-y+2), relative=0, thickness=0)
    return w


def page(number, chapter, title, subtitle, sources):
    rect(0, 0, W, H, BG, radius=0)
    rect(36, 28, 9, 9, TEAL, radius=2)
    text('LOCUS MEMORY', 53, 25, 10, INK, 'Bold')
    text(chapter.upper(), 828, 25, 9.5, MUTED, 'Bold', 'right')
    text(title, 36, 54, 31, INK, 'Bold')
    para(subtitle, 36, 98, 779, 12.2, MUTED, max_h=35)
    line(36, 541, 828, 541)
    x = 36
    text('SOURCE', x, 551, 8, MUTED, 'Bold')
    x += 45
    for label, url in sources:
        x += link(label, url, x, 549, 9) + 15
    text(f'0.3.0 DRAFT  /  04 OCT 2026    {number:02d} / 06', 828, 549, 9, MUTED, 'Body', 'right')
    c.bookmarkPage(f'page-{number}')
    c.addOutlineEntry(title, f'page-{number}', level=0)


def card(x, y, w, h, title, body, color=TEAL, fill=WHITE, tag=None, body_size=12):
    rect(x, y, w, h, fill, LINE)
    rect(x, y+16, 3, 28, color, radius=1)
    para(title, x+16, y+16, w-32, 16, INK, leading=19, max_h=42, font='Bold')
    title_lines = 2 if '<br/>' in title else 1
    body_y = y + (65 if title_lines == 2 else 48)
    para(body, x+16, body_y, w-32, body_size, MUTED,
         max_h=h-(body_y-y)-15-(25 if tag else 0))
    if tag:
        pill(tag, x+16, y+h-33, color, fill if fill != WHITE else GREY)


# 1. One runtime; two repositories.
page(1, 'The system map', 'A memory engine inside Locus',
     'Locus handles the conversation. The standalone package handles durable memory, review, retrieval and local persistence.',
     [('README', BASE+'README.md'), ('Host boundary', BASE+'docs/host-extraction.md')])

pill('LOCUS REPOSITORY', 36, 145, BLUE, PALE_BLUE)
pill('LOCUS-MEMORY REPOSITORY', 424, 145)
pill('ON YOUR DEVICE', 618, 145, MUTED, GREY)

card(36, 178, 166, 191, 'Locus app',
     'Chat turns<br/>Memory UI<br/>HTTP and model tools<br/><br/>Owns consent and model calls.', BLUE, PALE_BLUE)
card(230, 178, 166, 191, 'Host adapters',
     'Trusted identity<br/>Allowed scopes<br/>Profile path and keys<br/><br/>Calls the package API.', BLUE, PALE_BLUE)
card(424, 178, 166, 191, 'locus_memory',
     'Record lifecycle<br/>Search and context<br/>Encryption<br/>Migration and recovery', TEAL, PALE_TEAL, tag='IN-PROCESS PYTHON')
card(618, 178, 210, 191, 'Local memory store',
     'Encrypted records<br/>Deletion ledger<br/>Ownership control<br/><br/>User data stays outside both code repositories.', MUTED, WHITE)
arrow([(204, 263), (228, 263)], BLUE)
arrow([(398, 263), (422, 263)], TEAL)
arrow([(592, 263), (616, 263)], TEAL, both=True)

rect(424, 404, 404, 61, PALE_TEAL)
text('Approved, scoped context', 440, 415, 15, TEAL, 'Bold')
text('Selected for the query, kept within a budget, revalidated.', 440, 438, 11.4, MUTED)
arrow([(507, 371), (507, 402)])
rect(36, 404, 360, 61, PALE_BLUE)
text('Locus adds context to eligible model calls', 52, 415, 14, BLUE, 'Bold')
text('The model receives a packet, not direct vault access.', 52, 438, 11.3, MUTED)
arrow([(422, 434), (398, 434)])
para('<b>One local runtime.</b> The app imports its bundled engine directly. Memory needs no separate server, cloud account or GitHub connection at launch.',
     36, 490, 786, 12, INK, max_h=34)
c.showPage()


# 2. Creation and serving have different gates.
page(2, 'A memory through time', 'Only reviewed memories enter recall',
     'Agent suggestions wait for user approval. Later, the engine selects only the memories allowed for the current request.',
     [('Lifecycle API', BASE+'src/locus_memory/compat/canonical_vault.py'), ('Recall runtime', BASE+'src/locus_memory/runtime.py')])
text('SAVE AND REVIEW', 36, 145, 10, MUTED, 'Bold')
xs = [36, 234, 432, 630]
steps = [
    ('1  Propose', 'A tool or selected chat suggests a useful fact.', BLUE, PALE_BLUE),
    ('2  Candidate', 'Stored for review. Excluded from automatic recall.', AMBER, PALE_AMBER),
    ('3  User review', 'A person approves or rejects the proposal.', BLUE, PALE_BLUE),
    ('4  Approved', 'Eligible for recall within its allowed scope.', TEAL, PALE_TEAL),
]
for x, (title, body, color, fill) in zip(xs, steps):
    card(x, 166, 174, 110, title, body, color, fill, body_size=11.8)
for x in [210, 408, 606]:
    arrow([(x+2, 221), (x+22, 221)], MUTED)
text('Authorized user-created memories can also be saved directly as approved.', 36, 286, 10.8, MUTED)

text('RECALL FOR AN ELIGIBLE CHAT TURN', 36, 320, 10, MUTED, 'Bold')
recall = [
    ('Policy', 'Is memory allowed for this turn?'),
    ('Scope', 'Check trusted grants before decrypting.'),
    ('Retrieve', 'Rank relevant approved records.'),
    ('Compile', 'Build a packet within the token budget.'),
    ('Revalidate', 'Check grants, changes and deletions again.'),
    ('Submit', 'Send as reference data; record receipt.'),
]
for i, (title, body) in enumerate(recall):
    x = 36 + i*134
    rect(x, 342, 122, 106, WHITE, LINE)
    text(title, x+12, 355, 13.3, TEAL, 'Bold')
    para(body, x+12, 380, 98, 11.4, MUTED, max_h=58)
    if i < 5:
        arrow([(x+124, 395), (x+132, 395)], TEAL, width=1.2)

rect(36, 475, 792, 49, INK)
text('CORRECT OR FORGET', 52, 485, 9.5, '#AADBD0', 'Bold')
para('Corrections create revisions. Forgetting records deletion and removes affected data; both invalidate affected context. Text already sent to a provider cannot be recalled.',
     210, 484, 600, 11.2, WHITE, leading=14.6, max_h=32)
c.showPage()


# 3. Module map: concrete files without a code dump.
page(3, 'The key parts', 'Eight parts, one reusable package',
     'The package owns memory behavior. Locus supplies application capabilities through explicit adapters and callbacks.',
     [('Module map', BASE+'README.md#package-modules'), ('Host extraction', BASE+'docs/host-extraction.md')])

modules = [
    ('Memory API', 'Create, search, approve, correct, forget and exchange records.', 'engine.py + compat/', TEAL),
    ('Recall runtime', 'Coordinate recall, shadow comparison, revalidation and maintenance.', 'runtime.py', TEAL),
    ('Retrieval + context', 'Rank approved records and compile a bounded context packet.', 'retrieval/ + context/', TEAL),
    ('Encrypted storage', 'Seal payloads, separate partitions and track durable deletion.', 'storage/ + crypto.py', TEAL),
    ('Policy + access', 'Define recall budgets, scope grants and permitted operations.', 'policies.py + models.py', BLUE),
    ('Candidate learning', 'Review selected-chat suggestions; support richer learning APIs.', 'learning/', BLUE),
    ('Continuity + history', 'Compose task context, index saved chats and optionally archive history.', 'context/ + history/', BLUE),
    ('Setup + migration', 'Initialize fresh stores; snapshot, validate, cut over and roll back.', 'bootstrap.py + migrations/', BLUE),
]
for i, (title, body, module, color) in enumerate(modules):
    x = 36 + (i % 4)*201
    y = 155 + (i // 4)*148
    rect(x, y, 189, 133, WHITE, LINE)
    dot(i+1, x+13, y+13, color)
    text(title, x+13, y+44, 13.8, INK, 'Bold')
    para(body, x+13, y+67, 164, 11.4, MUTED, max_h=47)
    text(module, x+13, y+115, 8.7, color, 'Mono')

rect(36, 460, 792, 64, PALE_BLUE)
text('STAYS IN LOCUS', 52, 471, 9.5, BLUE, 'Bold')
para('UI and tool routes, user consent, trusted identity, keys, paths, sessions, scheduling and model calls.',
     180, 468, 625, 12, INK, max_h=32)
para('0.3.0 source integrates episodes, procedure review, inspector and local embeddings. Tests and release remain deferred.',
     52, 499, 751, 10.3, MUTED, max_h=18)
c.showPage()


# 4. Storage and trust boundaries.
page(4, 'Data and authority', 'Where the data lives - and who controls it',
     'Paths shown use the standard Locus profile. Scope checks, host consent and provider policy determine what can be read or sent.',
     [('Data locations', BASE+'README.md#code-ownership-and-data-location'), ('Access model', BASE+'src/locus_memory/models.py')])

rect(36, 154, 386, 189, PALE_TEAL)
pill('NATIVE ENGINE STORE', 52, 166)
text('~/.ollama-code/memory-engine/', 52, 199, 11.2, TEAL, 'Mono')
para('<b>Encrypted payloads:</b> records, native history and vectors use AES-256-GCM. Search projections are held in memory.',
     52, 224, 353, 12, INK, max_h=50)
para('Ownership control and some metadata remain visible. Locus supplies the key provider; the host key stays in <font name="Mono" size="9.4">memory/master.key</font>.',
     52, 284, 353, 11.3, MUTED, max_h=47)

rect(440, 154, 388, 189, WHITE, LINE)
pill('COMPATIBILITY + HOST FILES', 456, 166, AMBER, PALE_AMBER)
text('memory/memory.sqlite3', 456, 199, 10.9, MUTED, 'Mono')
para('Legacy encrypted continuity and observation families; also retained for memory rollback.',
     456, 219, 355, 11.6, INK, max_h=33)
text('transcript-index.sqlite3', 456, 266, 10.9, AMBER, 'Mono')
para('0.3.0 encrypts the saved-chat cache; FTS stays in RAM. Raw session files remain outside this change.',
     456, 286, 355, 11.6, INK, max_h=40)

for x, title, body, color in [
    (36, 'User', 'Can approve, correct or forget through authorized Locus routes.', BLUE),
    (306, 'Agent tools', 'Can read permitted memory and propose candidates. Cannot approve.', TEAL),
    (576, 'Trusted host', 'Supplies the partition, identity, personal/workspace/agent grants and keys.', MUTED),
]:
    rect(x, 364, 252, 82, WHITE, LINE)
    text(title, x+15, 375, 14, color, 'Bold')
    para(body, x+15, 399, 222, 11.4, MUTED, max_h=36)

rect(36, 469, 792, 55, PALE_AMBER)
text('THE MODEL BOUNDARY', 52, 480, 9.5, AMBER, 'Bold')
para('Memory is lower-priority reference data. Native Codex is opt-in per agent. Provider copies cannot be retracted; macOS Keychain checkpoints detect restored deletion history.',
     206, 479, 603, 11.3, INK, leading=14.7, max_h=36)
c.showPage()


# 5. Acquisition and ownership are separate transitions.
page(5, 'Delivery and changeover', 'Install once. Move ownership safely.',
     'The released app bundles 0.2.1. The 0.3.0 wheel and app update wait for acceptance checks; completed cutover is preserved.',
     [('Fresh setup', BASE+'src/locus_memory/bootstrap.py'), ('Host integration', BASE+'docs/host-extraction.md'), ('Public release', REPO+'/releases/tag/v0.2.1')])

text('AUTOMATIC DELIVERY', 36, 144, 10, MUTED, 'Bold')
delivery = [
    ('Public wheel', '0.2.1 now; 0.3.0 pending'),
    ('Build verifies', 'Fixed URL + SHA-256'),
    ('Signed Locus app', 'Engine bundled inside'),
    ('Fresh profile', 'Encrypted store + recall'),
]
for i, (title, body) in enumerate(delivery):
    x = xs[i]
    rect(x, 166, 174, 71, PALE_TEAL)
    text(title, x+13, 180, 14.5, TEAL, 'Bold')
    text(body, x+13, 206, 10.7, MUTED)
    if i < 3:
        arrow([(x+177, 201), (x+195, 201)])
text('No setup commands or launch-time code download. Existing stores are never overwritten by fresh initialization.',
     36, 247, 10.9, MUTED)
text('Legacy rollout: shadow compares recall; enabled serves engine context. Neither flag transfers storage ownership.',
     36, 264, 10.5, MUTED)

text('EXISTING LEGACY PROFILE', 36, 283, 10, MUTED, 'Bold')
text('Stop writers; hold an exclusive profile lease.', 828, 282, 10.7, MUTED, align='right')
migration = [
    ('Inventory', 'Check source records, scopes and owner.'),
    ('Snapshot', 'Snapshot encrypted data; import the copy.'),
    ('Validate', 'Verify records, lifecycle and mapped scopes.'),
    ('Cutover', 'Fence writers, sync, then switch owner.'),
]
for i, (title, body) in enumerate(migration):
    x = xs[i]
    card(x, 306, 174, 100, title, body, BLUE, WHITE, body_size=11.3)
    if i < 3:
        arrow([(x+177, 356), (x+195, 356)], BLUE)

rect(36, 437, 222, 42, PALE_BLUE)
text('Legacy authoritative', 52, 448, 13.5, BLUE, 'Bold')
rect(606, 437, 222, 42, PALE_TEAL)
text('Package authoritative', 622, 448, 13.5, TEAL, 'Bold')
arrow([(717, 408), (717, 435)])
arrow([(603, 460), (262, 460)], BLUE)
text('Rollback preview + reverse-sync', 432, 428, 11.2, BLUE, 'Bold', 'center')
text('Preserves representable corrections and deletions.', 432, 470, 9.6, MUTED, align='center')

para('<b>Ownership persists.</b> A rollout flag cannot undo cutover. Legacy continuity families keep their existing format; encrypted transcript archival remains opt-in.',
     36, 493, 791, 11.3, INK, max_h=31)
text('0.2.1 is published. The 0.3.0 update awaits acceptance and the normal Locus application release.',
     36, 525, 9.2, MUTED)
c.showPage()
# 6. Visibility and governed learning added in the current working tree.
page(6, 'Visibility and learning', 'Inspect evidence. Verify before reuse.',
     'Source implementation for 0.3.0. Remaining tests, evaluation reruns and signed-app release are deferred at the user\'s request.',
     [('Feature matrix', BASE+'docs/feature-matrix.md'), ('Validation record', BASE+'docs/release-0.3.0.md')])
card(36, 151, 250, 177, 'Per-turn inspector',
     '<b>Submitted to model</b><br/>Agent and attempt<br/>Scope and match reasons<br/>Budget and exclusions<br/>Changes on revalidation<br/><br/>Current authorized content only.', BLUE, PALE_BLUE, body_size=11.3)
card(307, 151, 250, 177, 'Verified episodes',
     'Terminal task evidence is saved automatically when memory is enabled.<br/><br/>Actual check receipts bind task revision and file fingerprints. Claims of success remain unverified.', TEAL, PALE_TEAL, body_size=11.5)
card(578, 151, 250, 177, 'Reviewed procedures',
     'Two independent successes<br/>Human-approved test suite<br/>Negative cases<br/>Disposable worktree checks<br/>Human approval<br/><br/>No automatic installation.', BLUE, PALE_BLUE, body_size=11.3)
arrow([(288, 240), (305, 240)], MUTED)
arrow([(559, 240), (576, 240)], MUTED)
rect(36, 349, 386, 91, WHITE, LINE)
text('Optional local semantics', 52, 362, 15, TEAL, 'Bold')
para('Select an installed Ollama embedding model. No download. Scoped keyword + vector ranking; encrypted vectors. Failures use keywords.', 52, 387, 353, 11.6, MUTED, max_h=47)
rect(442, 349, 386, 91, WHITE, LINE)
text('Deletion restore guard', 458, 362, 15, BLUE, 'Bold')
para('The signed macOS helper keeps a monotonic Keychain checkpoint. Missing or divergent history makes memory unavailable until reviewed recovery.', 458, 387, 353, 11.6, MUTED, max_h=47)
rect(36, 465, 792, 61, PALE_AMBER)
text('QUALITY GATE STILL OPEN', 52, 477, 9.5, AMBER, 'Bold')
para('Initial six-task campaign: 2/6 with memory and 2/6 without. Source review points to an overly strict filter; the saved run cannot prove the cause. Later changes are untested.', 237, 475, 572, 11.4, INK, max_h=42)
c.showPage()

c.save()
print(OUT)
