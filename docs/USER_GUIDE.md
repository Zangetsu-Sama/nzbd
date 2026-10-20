# nzbd user guide

Getting NZBs in, searching, exploring a release, and the admin pages.

## Getting NZBs in

| Way | How | Notes |
|---|---|---|
| Watch folder | Copy or move `*.nzb` into `data/watch/` | Picked up after a stability check; the file is moved into the store, never left behind. Duplicates (same SHA-256) go to `duplicates/`, unreadable or hostile files to `failed/` with a `reason.json`. The operator can add **watch-folder rules**: a sub-folder or a file-name pattern gives new releases a category and/or a source label (for example everything dropped into `data/watch/From Seedbox/` is labelled `seedbox`). Rules never apply to the upload form or the API, and never relabel a release that is already indexed. |
| Upload form | **Upload** in the sidebar | Several files at once, optional category (default: Scene-name rules) and a free-text **Source** label applied to every file. Per-file result list. Add each release's `.nfo` to the same selection to attach it (see below). |
| API | `POST /api/v1/nzb` with `X-Api-Key` (create keys on the Account page or `nzbd apikey create`) | Upload only; nothing can be read back through the API. Behind the proxy you also send the proxy credentials. A multipart upload may carry the NFO as a part named `nfo`. |
| Bulk import (operator) | `nzbd import <dir>` on the host (RUNBOOK section 5) | Fills a new library from a directory of NZB files, for example the `data/store/` of an earlier install. The directory is only read: nothing in it is moved or deleted. Run it again at any time; files already in the library are skipped. |

**Release titles** come from the `.nzb` file name when it looks like a real name: an NZB dropped or uploaded as
`Some.Movie.2024.1080p-GRP.nzb` is titled `Some.Movie.2024.1080p-GRP` even when everything inside is obfuscated. Names
that say nothing (`download.nzb`, `download (1).nzb`, `12345.nzb`, a hash such as `d41d8cd98f00b204e9800998ecf8427e.nzb`)
are skipped and the title comes from the NZB metadata, else from the inner file names. Uploading the same NZB again under
another name keeps the first title.

**NFO files.** Select the `.nfo` together with its `.nzb` in the upload form (`Show.S01E01.nzb` and
`Show.S01E01.nfo`; the case of the names does not matter, and with one NZB and one NFO the names do not matter at
all). The Family filter lists TV, Anime, Movie, Music and Game (no release is classified as Game yet). Releases with an NFO carry an **NFO** badge in the index. The NFO is hidden on the release page until you press **Show NFO** (**Hide NFO** closes it again); it is then shown as the classic DOS art (code page 437, the "true" NFO view), with a full
view, a UTF-8 switch for the few NFOs written in UTF-8, and a **Download .nfo** link. Up to 256 KiB per NFO. Only the
uploader of a release or an administrator can add its NFO, and only while it has none; an administrator can remove it
(**Remove NFO**) so a better one can be uploaded with the NZB again. With the API:
`curl -H "X-Api-Key: $KEY" -F file=@Show.S01E01.nzb -F nfo=@Show.S01E01.nfo https://nzbd.lan/api/v1/nzb`.
**NFO in the watch folder.** Put the NFO next to its NZB with exactly the same name: `Foo.Bar-GRP.nzb` and
`Foo.Bar-GRP.nfo` (the `.nfo` extension may be in any case, `.NFO` works too; the rest of the name must match letter
for letter). When the NZB is ingested the NFO is attached to its release (only if the release has none yet, also when
the NZB was already in the library) and leaves the watch folder with the NZB: removed once it is stored, or moved next
to the NZB into `failed/` or `duplicates/` under the same name with `.nfo`; `nzbd failed retry` brings it back
together with the NZB, expiry moves it to `failed/expired/` with it, and purging that failed item removes both. An NFO
that cannot be attached (empty, larger than 256 KiB, or the release already has another one) is never deleted: you find
it in `failed/` (or `duplicates/`) as `<date>-<hash>.nfo`; the log says why (`NFO_EMPTY`, `NFO_TOO_LARGE`, `NFO_EXISTS`,
...) and names that file. Symbolic links, hard-linked files, two NFOs whose names differ only by case, two NZBs whose
names differ only by case (`Foo.nzb` and `Foo.NZB` while both are there), and an NFO whose target name is already taken
are left untouched where they are. Drop the NFO together with or before the NZB: an NFO that arrives after its NZB was
ingested, or one without an NZB, simply stays in the watch folder (an NFO is never ingested on its own); drop the
NZB again next to it, or upload both in the upload form. NFO text is never searchable.

## The index

![Index](ui/index-chromium-light-1440.png)

The home page lists releases (50 per page; choose 25, 50 or 100 with **Per page** under the table) with title, category, when it was posted ("12 months ago (2025-10-09)";
hover for the exact time), size, file count, source and status badges. Each row only shows what says something:

- the original file name appears under the title only when it differs from the title (it is usually the title plus
  `.nzb`);
- the category badge appears only for **Fallback** (no rule matched) and **Manual** (someone chose it); the release page
  shows how every category was decided; the **Uncategorized** status badge goes away once a category is set by hand;
- the **Source** cell is one line: your source label if the release has one, otherwise how it arrived (*Watch folder*,
  *Upload*, *API*) in grey; a long label ends in "..." and the full text (with how it arrived) shows when you hover;
- a completeness bar appears only for a release with missing segments (none today: nzbd does not check a news server
  yet);
- the **Download** button at the end of the row downloads that release's NZB, exactly like Download on its release
  page (every role).

A line next to the page title sums up the library ("68 releases · 1,578 segments · 1.0 GiB"), and the sidebar shows
how many releases each top-level category holds (click a category to open its sub-categories, for example Movies >
HD, PC > Games, Mac > MacGames or Console > Nintendo; XXX, when shown, is always last) (on the index page; hidden categories are never counted). On a phone
the navigation folds into a **Menu** button in the top bar, so the search box is on the first screen.

- **Search** matches words in the title, the inner file names, the poster, the original `.nzb` file name and the
  release group (`-GRPNAME`); all words must match (operators are stripped, so typing
  quotes or `OR` is harmless). The last word also matches longer words it starts with (`matr` finds `Matrix`). When
  nothing matches exactly, nzbd tries close spellings once and says **"No exact matches. Showing approximate
  matches."** (it never shows which words it tried).
- **Notices above the list** (fixed text): *Search narrowed* (a short last word matched too many words; type more of
  it), *More than n releases match* (counting all would take too long: the number is a lower bound, the page count and
  the Last link are left out, Next still works), and *The search index is being rebuilt* (after a restore or an index
  repair: the list shows the newest releases only, with the category filter; search, sorting and the other filters come
  back when the rebuild is done).
- With hidden categories, prefix and approximate searches show a fixed notice that they use a limited set of
  alternatives. It does not reveal whether hidden words exhausted a budget. Results remain approximate at the
  dictionary, posting or time limits; use more specific terms to find additional matches.
- New uploads and edits appear in the list and in search within a few seconds (the search index trails the database
  slightly); the release page itself is always current.
- **Filters**: the search row has the text, the category (children indented) and the **Search** button; **More filters**
  folds open below it with the date range (`YYYY-MM-DD`, UTC), min/max size in MiB, flags (par2, obfuscated), family
  (TV / Anime / Movie / Music), resolution, source, year and release group. The one Search button applies everything;
  **Clear filters** appears next to it while a filter is active.
- **Sort** by date (default), size or title; Previous/Next use cursors, so paging stays as fast at any depth (First, Last and numbered links are offset queries).
  A typed `page=N` deeper than 100,000 releases that is not near the end is refused (`BAD_QUERY`); use Next/Previous
  or Last instead.
- Categories follow a Newznab-style taxonomy (`nzbd categories` lists it). With `[ui] show_xxx = false` the XXX
  category is hidden everywhere, for everyone; each account can also hide it for itself (Account > Preferences).
- **Bulk actions**: tick the rows you want (the box in the header selects the whole page when JavaScript is on) and
  use the bar under the table, up to 100 releases per action.
  - **Download selected (.zip)** (every role): one file `nzbd-<n>-releases-<date>-<time>.zip` (UTC) holding the
    original NZB of each ticked release, named after its title (`My_Show_2020.nzb`; a second release with the same
    name gets its id added, `My_Show_2020-123.nzb`). The zip is not compressed (NZBs are small; any unzip tool opens
    it). A selection over 1 GiB of NZB files in total is refused ("Selection too large"). Releases that were deleted
    meanwhile, or that you cannot see, are simply left out. Only one bulk download runs at a time, and one per account
    (others get "Busy, try again shortly"; that does not count against your two per minute), and each account and
    address may start two per minute ("Too many requests" otherwise). A zip must finish within 4 and a half minutes
    and the download must keep moving: a very large selection on a slow connection can break off, so tick fewer
    releases then. If
    the server cannot read one of the NZBs, the download stops with an error in your browser instead of giving you an
    incomplete zip. Each bulk download is one entry in the audit log with the number of releases.
  - Admins also get **Set category** and **Set source label** (leave it empty to clear it) for all of them
    at once. Admins also get **Delete selected...**: a confirmation page lists the releases and asks for `DELETE`,
    your password and an authenticator code, then moves each NZB to the trash and reports per release. If one of the
    selected releases no longer exists, nothing is changed and you get "not found": reload the list and select again.
    Every change is in the audit log under your account.

### Saved searches

Any account can keep up to 25 saved searches; they are private (nobody else, not even an administrator, sees them) and
go away when the account is deleted.

- **Save**: search or filter on the index, then type a name in **Save this search as** (under the filters, 1 to 60
  characters) and press **Save this search**. What is saved is the search itself: the text, the category, the other
  filters and the sort order (not the page you were on). Names must be different from each other.
- **Sidebar**: on the index, the section **Saved searches** lists them. A badge such as **3 new** counts the releases
  that match the search and were added since you last opened it (it shows **99+** for more than 99). Opening a saved
  search (click its name) shows its results and resets the badge. If counting takes too long the badge is simply left
  out for that page view; it never slows the page down. Releases in a hidden category are never counted. The search
  index trails new uploads by about two seconds: a release added in the last couple of seconds before you open a saved
  search may not appear in its results yet and is then not counted as new afterwards either; one added in the same
  second as your visit may be counted once more.
- **Manage saved searches** (the last sidebar entry) lists them with their filters and lets you **Rename** or
  **Delete** each one. A saved search whose filter is no longer valid or available to you (for example a category you
  now hide) is listed as "can no longer be opened"; delete it and save a new one.

### Statistics
**Statistics** in the sidebar (or the Menu on a phone) shows numbers about the library: how many releases and how much
data, how many were added in the last 7 and 30 days, releases per category with total and average size, the top 10
release groups, the split by resolution, source, family and year, and releases added per month over the last two
years. Click a category, group, resolution, source, family or year to see those releases on the index. The numbers
only count what you can see (a hidden XXX category is left out) and are refreshed every 10 minutes; a part that
cannot be computed right now says so, try again a minute later.

## A release and the NZB explorer

![Release page](ui/release-chromium-light-1440.png)

The release page shows the parsed Scene info (family, year, season/episode, resolution, source, codec, group), how the
category was decided (Scene, Upload, Meta, Fallback or Manual), totals, when it was posted and indexed ("3 days ago
(2026-10-13 08:12 UTC)"), alerts (incomplete, obfuscated, executable, missing volume, par2) and the file table. The
alerts panel is blue when it only holds information (for example Par2), orange when something asks for attention and
red for a problem. The file table's **Completeness** column appears only when a file of the page has gaps, with a bar on
those files only. Here you can:

- **Download** the original NZB, byte-identical to what you ingested;
- **Download selected**: tick the files you want in the file table and press **Download selected** under it to get
  an NZB holding only those files (`<name>-partial.nzb`), for example one episode of a season pack or the par2
  files alone. It works without JavaScript; only the files of the page you are on can be ticked (100 per page by default; 50, 250 or 500 with **Per page** under the table). The
  partial NZB is written fresh from the indexed NZB (same head meta, the ticked files with all their segments); the
  stored NZB is never changed. One partial download runs at a time (others get "Busy, try again shortly"), and a
  selection whose NZB would exceed the NZB size limit is refused ("Selection too large");
- **Edit** the category and the source label (administrators; audited);
- read the **NFO** when one was uploaded with the NZB (full view, UTF-8 switch, **Download .nfo**; admins can remove it);
- open **Raw** to see the NZB head and meta (the only place an NZB password would appear);
- **Delete** the release (admins, from the **Danger zone** at the bottom of the Edit panel, away from Download):
  typed confirmation plus password and a fresh TOTP code; the NZB goes to a trash area.

![Segment explorer](ui/segments-chromium-light-1440.png)

Each file opens its segment list (number, bytes, message-id), with missing ranges called out. Because nzbd has no
news server, "missing" means gaps *inside the NZB itself* (declared segments that are absent); real availability is not
checked, so the index shows segment counts as `N/N`.

## Administration

![Admin](ui/admin-chromium-light-1440.png)

- **Admin**: ingest log, counters, audit tail. **Health**: app, database, ingest, storage and security/config checks with a hint when
  something is not OK, plus an on-demand deep check (also `nzbd health`).
- **Cleanup**: counts and sizes of Trash (deleted releases), Blocked (policy-rejected inputs) and Failed items, each
  purgeable on an explicit typed confirmation. `watch/`, duplicates and the live NZB store are never touched; Trash removes only what nzbd itself moved to its trash folders.
- **Account**: preferences (below), password change, recovery codes, sessions and API keys.

## Preferences (every account)

Account > **Preferences** holds settings that apply to your account only:

- **Hide XXX for me**: the XXX category and its subcategories disappear from your index, search, totals, sidebar counts,
  timeline, menus and category lists, and their release pages answer "not found" for you, exactly as if the operator had
  set `ui.show_xxx = false`. Other accounts are not affected. If the operator already hides XXX for everyone, the box is
  replaced by a note (you cannot show what the operator hid).
- **Theme**: *Automatic* (default: follows the light or dark setting of your device), *Light* or *Dark*. The sign-in
  pages and error pages always follow the device setting.
- **Rows per page**: how many releases the release list shows (25, 50 or 100) and how many files a release's file
  table shows (50, 100, 250 or 500). The same choice is made with **Per page** at the bottom right under each table:
  pick a number and press **Show**; you stay on the same search, filters and sort and go back to page 1. The largest
  release page (100) is also the most one bulk action accepts, so "select all" on a page always fits.

Saving shows "Preferences saved." (or "Nothing changed."); the audit log records which settings changed, never their
values.
- **Users** (administrators, only while `security.multi_user = true`): the accounts of this installation, who added what,
  invitations and recovery codes. See "Several accounts" below.

## Several accounts (optional)

By default nzbd has one account, an administrator. An operator can switch on `security.multi_user` (see
[CONFIGURATION.md](CONFIGURATION.md)); then several people share the **one library**, each with their own password and
authenticator:

| Role | Can |
|---|---|
| Viewer | Browse, search, open releases and the explorer, download NZBs (one, a selection of files, or several releases as a zip), save searches, see the statistics. |
| Uploader | Everything a viewer can, plus upload NZBs and create and revoke **their own** API keys (Account page; uploads through a key are attributed to you). An uploader cannot change the category or source label of any release, not even of its own uploads: ask an administrator. |
| Administrator | Everything above, plus change the category and source label of any release (also several at once; every edit is attributed), delete releases, the Admin, Health and Cleanup pages, every account's API keys (list and revoke), and the Users page. |

- **Invite someone** (administrator): Users, *Invite a user*, enter a login name and a role (uploader or viewer), confirm
  with your password and a fresh authenticator code. The code is shown once; hand it over out of band together with
  the address printed on the page (the invitation page is at `/invite` unless the operator moved it with
  `security.invite_path`; the page prints the right one). The sign-in page has no link to it, so always hand the address
  over together with the code. The invitee opens that address, enters the code, chooses a password, a **display name**
  and gives an **email address**, then scans the authenticator QR code. Their login name is shown to them only after
  the code was accepted. A display name that is already taken, or is someone's login name, is refused as "not
  available"; after 3 such refusals the invitation is cancelled and the invitee needs a new one.
- **Lost password or authenticator** (uploader or viewer): Users, *Issue recovery code*. Whoever redeems it at the
  invitation page (the address printed with the code)
  chooses a new password and a new authenticator; nothing changes for the account until they confirm, and you can cancel
  a pending recovery. Administrator accounts cannot be recovered or changed on the web: the operator uses the `nzbd`
  command line on the host (RUNBOOK section 5), and the web can only *Revoke sessions* of an administrator.
- **Who added what.** Each release shows "Added by" with the person's *display name*, which every role can see. An
  invited person chooses it when accepting the invitation (3 to 32 letters, digits, `-` or `_`; it can never be a login
  name); accounts created with `nzbd user create` start as `user-<number>`. An administrator can change it later; you
  cannot change it yourself. Login names are visible to administrators only.
- **Email.** The email given at the invitation is visible only to you (Account page) and to administrators (Users page
  and `nzbd user list`). nzbd never sends mail and never contacts anything with it; it is removed when the account is
  deleted.
- **Pages you may not use** look exactly like pages that do not exist (404). That is deliberate; ask an administrator
  for a higher role.
- If the operator also sets `security.registration_enabled = false` there are no invitations at all: accounts are created
  with `nzbd user create`, and the invitation page accepts only recovery codes.

## Day-2 in one screen

| Task | Command (inside the `nzbd` container: `docker compose exec nzbd /nzbd ...`) |
|---|---|
| Is it healthy? | `health`, `healthcheck`, `db check [--full]` |
| Backup | `backup` (also scheduled in-process); restore steps in RUNBOOK section 2 |
| Failed files | `failed list`, `failed retry <name>` |
| Accounts | `user create [--role R]`, `user list`, `user set-role`, `user invite`, `user disable|enable|delete|unlock`, `user reset-password`, `user reset-mfa`, `apikey create|list|revoke` |
| Storage | `store verify`, `store gc`, `store migrate --to db|fs` |
| Trash and cleanup | `trash list|restore|purge`, `cleanup status|purge` |

Full command table: [RUNBOOK.md](RUNBOOK.md) section 7.
