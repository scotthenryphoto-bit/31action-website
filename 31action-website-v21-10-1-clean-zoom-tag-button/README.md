# 31 ACTION — v6

This version keeps the existing 31 ACTION visual theme and rebuilds the photo-management pieces that were causing trouble.

## Everyday workflow
1. Put portfolio photos in `images/sports`, `images/portraits`, `images/events`, or `images/other`.
2. Put landing/slideshow photos in `images/landing`.
3. For each Recent Shoot, make a folder inside `images/recent-shoots` and put that event's photos inside it.
4. Double-click `UPDATE_IMAGES.bat` after changing any photo folders.
5. Press `Ctrl+F5` in the browser after updating.

## Recent Shoot folder names
If a folder begins with a date, the site formats it automatically. Example:

`6 15 26 7 on 7` → `06-15-2026 7 on 7`

It also understands separators such as `6-15-26`, `06_15_2026`, and `6.15.26`.

If there is no date in the folder name, the updater tries to read the EXIF capture date from the first photo and prepend it to the gallery title.

## No cropping in galleries
Portfolio galleries and Recent Shoot galleries preserve each photo's natural aspect ratio. Vertical stays vertical and horizontal stays horizontal. Clicking a photo opens the complete image in the lightbox. Keyboard Left/Right arrows move through the gallery.

## Landing Photo Editor
Open `crop-tool.html`.
- The bright rectangle shows what the visitor sees.
- The dark overlay shows what will be cropped.
- Click/drag to place the red focal marker over the important subject.
- You can preview desktop and phone separately.
- `Save Crop on This Computer` changes the homepage in the same browser.
- Before publishing to another computer/server, use `Download crops.js` and replace `assets/js/crops.js` with that downloaded file.

## Cart feedback
Once a customer adds a product from a photo, that photo card gets a red outline and an `Added to Cart` badge. It also lists exactly which sizes/digital products and quantities from that photo are in the cart.

## Shopping / payments
This is still a test store. It does **not** collect credit-card numbers. The cart collects customer identity, email, phone, shipping address when prints are ordered, exact gallery/photo/product/quantity, amounts, and order notes. Stripe should handle live card data later.

## Sales dashboard
Open `sales.html`. It is intentionally not linked in the public navigation. Until Stripe + a backend/database are connected, it shows only test orders created in the same browser. A static HTML site cannot see purchases made by customers on other computers.

## Footer
The footer 31 ACTION mark now matches the header: 31 is white, ACTION is red, and the old vertical line is removed.

V7 UPDATES
- Recent Shoots event covers and gallery photos never use fixed-aspect cropping; vertical and horizontal photos display in full.
- Landing Crop Editor now uses a movable/resizable crop box. Desktop and Phone crops are saved separately.

## v8: Ordering from the full-screen viewer
In Recent Shoots, clicking a photo opens the full uncropped image. If products from that photo are already in the cart, the zoomed photo keeps the red border and Added to Cart badge. A small Order This Photo control sits at the lower-right. On desktop it expands on hover or click; on phones/tablets it expands on tap. Customers can select a product and quantity and add it to the cart without closing the full-screen viewer.


## v9 Admin prototype
Open `admin.html` to preview the new owner workflow. It can select a full-resolution folder locally, infer common folder-date formats, preview automatic watermarking, display the agreed digital package pricing, and save demo complimentary-access grants. The Cloudflare parts are deliberately not live until your account is connected and authentication is configured. A `cloudflare-worker/` starter folder is included for the eventual R2 + D1 backend.

The Landing Crop Editor also supports Desktop/Phone exclusions and drag-and-drop slideshow ordering.


## v10 updates
- Recent Shoots now includes a calendar date picker, event-name search, Newest/Oldest sorting, and Clear button.
- Digital package pricing is automatically calculated in the test cart: any 3 for $35, any 5 for $50, any 10 for $85.
- Cart prompts customers when they are close to the next package.
- Cloudflare Worker starter now uses the actual R2 bucket names: `31action-photos` as `ORIGINALS` and `31action-previews` as `PREVIEWS`.
- Admin upload routes now require an `ADMIN_TOKEN` secret before accepting writes.
- Do not deploy the Worker API until D1 and authentication are configured. The static website can remain live independently.


## v11 Admin + API
- Admin page connects to https://api.31action.com
- Originals upload privately to 31action-photos
- Browser-generated watermarked previews upload to 31action-previews
- Gallery/photo records save to D1
- Recent Shoots and shoot.html load Cloudflare galleries automatically
- ADMIN_TOKEN is entered at runtime and can be held in sessionStorage for the current browser tab only; it is never hardcoded in the site.


## v11.1 admin fix
- Adds Test Token button before uploads.
- Normalizes token input so raw tokens and values beginning with `Bearer ` both work.
- Adds recursive drag-and-drop folder reading in Chrome/Edge while keeping click-to-select folder support.


## v11.2
- Adds Admin Archive / Restore / permanent Delete gallery controls.
- Permanent Delete refuses galleries that already have purchase records.
- Adds None / Light / Standard / Strong watermark modes with visibly different layouts.
- Strong watermark is less dense than the previous version.


## v12 Site Manager
- Portfolio Manager uploads finished JPGs to Cloudflare R2.
- Portfolio photos can be moved between categories, reordered, archived/restored, deleted, and included on the homepage slideshow.
- Public Portfolio pages use Cloudflare-managed images when available, with the existing static portfolio as a fallback.
- About and Contact content can be saved as drafts and published from Admin.
- Homepage uses Cloudflare portfolio images marked for Home when available; otherwise it retains the existing local slideshow.
- Run the v3 D1 migration and deploy Worker v3 before deploying this website version.

## v12.1 Admin gallery fix
- Recent Galleries loads from the public API immediately instead of waiting on Admin authentication.
- Admin gallery details and Archive/Delete controls are layered on only after a valid token is available.
- An Admin endpoint failure no longer leaves the gallery list stuck on “Loading…”.
- Clear warnings/errors are shown in the Admin page when a request fails.

## v13 Visual + SEO
- Adds visual-editor.html for drag-and-drop portfolio/homepage curation.
- Shows existing static portfolio images and can import them into Cloudflare management.
- Adds per-photo accessibility/SEO metadata fields.
- Adds seo-manager.html for page title, description, focus phrases, canonical and social-sharing text.
- Adds robots.txt and sitemap.xml.
- Adds required personal-use licensing acknowledgement in the cart and license.html.
- Requires D1 migration v4 and Worker v4 before the new SEO/photo metadata tools can save.

## v13.1 Visual Editor Rebuild
- Visual Editor now renders a close approximation of the live homepage and portfolio pages.
- Drag any Cloudflare-managed photo onto Sports/Portraits/Events/Other on the homepage to move it into that category and make it first/cover.
- Clicking Edit Gallery opens the corresponding visual portfolio layout.
- Drag photos within a portfolio to reorder them.
- Drag photos onto category targets to move them between categories.
- Existing static site photos remain visible and can be imported into Cloudflare management.
- Clicking a managed photo opens Display/Crop, Details/SEO, and Move/Archive/Delete controls.
- Public homepage category covers automatically use the first Cloudflare-managed image in each category when available.
- No Worker or D1 change is required beyond the already-deployed v13 requirements.

## v13.2 Admin Controls
- Visual editor right-side photos now have Portfolio category dropdown, Cover Photo checkbox, and Homepage Slideshow checkbox.
- Gallery deletion uses a checkbox confirmation instead of requiring typed DELETE.
- Admin footer link routes through admin-gate.html and requires the Admin token before redirect.
- Admin pricing manager publishes product/print/package pricing to D1; public gallery/cart can load it dynamically.
- Recent Galleries include Open in Editor; recent-gallery-editor.html can remove individual photos.
- Individual recent-gallery photo deletion is blocked if purchase records exist.
- Requires D1 migration v5 and Worker v5.

## v13.3 Portfolio Fix
- Fixes the bug where adding/importing one Cloudflare image caused the rest of a category's original site photos to disappear.
- Public portfolio pages now merge Cloudflare-managed photos with the built-in site portfolio instead of replacing the whole category.
- Duplicate filenames are suppressed on public portfolio pages so accidental repeated imports do not repeat the same photo to visitors.
- Every photo in the Visual Editor now has the same Portfolio dropdown, Cover Photo checkbox, Homepage Slideshow checkbox, Crop/Edit button, Confirm delete checkbox and Delete/Remove button.
- Built-in site photos are managed through D1 settings without requiring an R2 import just to move/hide/use them.
- Moving one built-in photo to another category affects only that photo.
- Removing a built-in photo hides it from public portfolio/home displays without deleting the bundled source file.
- Cloudflare portfolio photos can be permanently deleted with checkbox confirmation.
- Requires D1 migration v6 and Worker v6.

## v13.4 Cover + Crop Sync
- Fixes missing public legacyPortfolioSettings API helper that prevented saved cover selections for built-in photos from appearing on the live homepage.
- Public portfolio/settings GET requests use no-store so editor changes are visible immediately instead of relying on a cached response.
- Homepage category covers now apply the saved desktop/mobile crop position.
- Visual Editor homepage category boxes use the exact same cover/crop calculation as the live homepage.
- Visual Editor hero preview also applies Cloudflare/D1 crop settings.
- Adds Open Live Homepage button to the Visual Editor for quick verification.
- No D1 migration or Worker update required beyond V6.

## v13.5 Chrome Cover Render Fix
- Fixes saved cover crops appearing wrong immediately after refresh but correct after resizing Chrome.
- Reapplies object-position after image load, double requestAnimationFrame, short layout-settle delays, font readiness, and tile ResizeObserver changes.
- Homepage and Visual Editor use the same shared cover renderer.
- No D1 or Worker changes required.

## v13.6 Deterministic Cover Crop
- Replaces Chrome repaint/reflow workaround with a deterministic focus + zoom renderer.
- Existing x/y/w/h crop records are preserved and converted at render time.
- Crop position controls object-position and transform-origin.
- Crop box size controls zoom (smaller crop = stronger zoom).
- Editor includes a live cover preview using the exact same rendering code as the public homepage.
- Crop Save re-reads the stored value from the API before redrawing the editor.
- No D1 or Worker update required.

## v13.7 Exact Cover Crop
- Replaces CSS approximation with pixel-accurate geometry based on actual image and container dimensions.
- Computes the true cover scale from natural image dimensions and live tile dimensions.
- Saved crop center becomes the focal point; saved crop size becomes zoom.
- Clamps the rendered image so blank areas can never enter the cover box.
- Editor live cover preview and public homepage use the same renderer.
- ResizeObserver only recalculates geometry when the destination box truly changes size; it does not alter saved crop values.
- No D1 or Worker update required.

## v13.8 True Crop Box
- Fixes the root cause exposed by portrait images: crop coordinates were being measured against the black editor stage rather than the displayed photograph.
- Crop x/y/w/h are now percentages of the actual photograph only.
- White crop rectangle is positioned over the real contained image bounds and cannot move into letterbox/pillarbox black space.
- Crop box stays locked to the homepage cover aspect ratio.
- The exact selected source rectangle is scaled to the live homepage cover.
- Live preview and homepage use the same source-rectangle renderer.
- Existing crops should be re-saved once in this editor because older versions may have stored coordinates relative to the black stage.
- No D1 or Worker update required.

## v13.9 Simple Crop + Black Bars
- Simplifies crop editing to one photograph with one movable/resizable white rectangle.
- The rectangle is free-form; it is no longer forced to the homepage aspect ratio.
- Everything inside the white rectangle is preserved in the cover.
- The live cover uses fit behavior for the selected crop, so vertical selections can show black side edges rather than being cropped again.
- Live preview sits beside the crop editor and uses the same renderer as the homepage.
- No D1 or Worker update required.

## v13.10 Landing Slideshow Fix
- Restores the landing-page slideshow after Cloudflare portfolio/home images are loaded asynchronously.
- site.js now waits for hero-slide elements to exist before starting the 5.2-second rotation.
- MutationObserver handles delayed slide insertion.
- hero:rebuilt event lets the homepage explicitly restart slideshow logic after rebuilding slides.
- No Worker or D1 changes required.

## v13.11 Slideshow Crop Sync
- Fixes homepage slideshow ignoring saved crop selections.
- Managed slideshow slides are no longer plain CSS background images.
- Each managed slide now contains an image rendered through ActionPortfolio.applyCover(), the same exact crop renderer used by homepage cover photos.
- Desktop/mobile crop selections and black-edge behavior are honored per slide.
- Static landing images remain as fallback if no managed slideshow images are selected.
- No D1 or Worker changes required.

## v13.12 Unified Landing Crop
- Removes the old local crops.js / download workflow from crop-tool.html.
- Landing Crop Editor now lists the actual photos currently enabled for Homepage Slideshow.
- Saving a crop writes directly to the same Cloudflare/D1 portfolio or legacy photo record used by the live homepage.
- Desktop and Phone crops remain independent.
- Live preview uses the same ActionPortfolio.applyCover renderer as the homepage slideshow.
- This eliminates the two competing crop systems that caused crop-tool selections to differ from the live site.
- No new D1 migration or Worker update is required beyond Worker V6 / current schema.

## V14 Unified Visual Editor
- One visual editor navigation row: Homepage, Landing Slideshow, Sports, Portraits, Events, Other, Recent Shoots.
- Removes separate Landing Crop Editor from normal workflow; crop-tool.html redirects to visual-editor.html.
- Canonical landing_slides table manages built-in landing images and portfolio-added slideshow images together.
- Each slide has independent Desktop crop, Phone crop, order, include/exclude, and Display Time (1–60 seconds).
- Homepage slideshow reads landing_slides directly and honors per-slide duration.
- Category cover crop is separate from slideshow crop.
- Black bars are allowed for vertical/portrait compositions.
- Requires D1 migration V7 and Worker V7.

## V14.1 Auth + Landing Slideshow Fix
- Fixes misleading "Token not accepted" messages after successful authentication.
- Visual Editor now distinguishes authentication failure from a later API/data loading failure.
- Admin token tester now confirms authentication separately from loading dashboard sections.
- Worker V7.1 fixes landing_slides sync/add operations against D1 partial unique indexes by using INSERT OR IGNORE.
- No D1 migration required.

## V14.2 Homepage Slideshow Visibility Fix
- Fixes black landing hero when the first database slide is excluded or skipped.
- The first successfully rendered slide now receives the active class.
- If every managed slide is excluded or fails to load, the homepage falls back to the original bundled landing slideshow instead of showing black.
- Broken image records no longer stall the entire slideshow build.
- No Worker or D1 update required.

## V14.3 Homepage Render Fix
- D1, slideshow records, editor connection, timing controls and crop editor were confirmed working.
- Fixes the remaining public-homepage-only rendering failure.
- Every public slide now displays its source image immediately as a safe background.
- Exact crop rendering waits until both image dimensions and hero destination dimensions are non-zero.
- Exact crop layer replaces the safe background only after successful rendering.
- If any crop rendering fails, the source image remains visible instead of producing a black hero.
- Per-slide timing remains active.
- Black bars remain permitted for portrait/vertical crops.
- Website only: no D1 or Worker update required.

## V14.4 Hero Sizing Fix
- Grounded in Chrome Console error: "Crop destination never became measurable".
- Explicitly sizes #slides and each .hero-slide to the rendered hero width/height.
- Pins #slides to current hero pixel dimensions and updates on browser resize.
- Crop renderer falls back to measuring the closest .hero if an absolute slide reports 0x0.
- No Worker or D1 change required.

## V15 Visual Workflow
- Keeps the main Admin page and its full-folder Recent Shoot drop uploader unchanged.
- Homepage tab is now a true manual preview with Desktop/Phone modes, Previous/Next slideshow controls, current file/timing display, Recrop Current, and cover-edit buttons.
- Landing Slideshow is redesigned as a large batch crop workflow:
  - Crop All Desktop, then Crop All Phone.
  - Large source image.
  - Device-shaped crop frame.
  - Save & Next workflow.
  - thumbnail filmstrip, slideshow order, timing, include/exclude.
  - Fit Entire Photo / Black Bars option.
  - keyboard Left/Right and Ctrl+S shortcuts.
- Sports/Portraits/Events/Other tabs now accept drag/drop or file selection directly into that category.
- Recent Shoots tab can add extra photos directly to an existing shoot with watermark choice.
- Recent Gallery Editor also has drag/drop file upload.
- Uses existing Worker V7.1 and D1 V7; no migration or Worker change required.

## V15.1 Mobile Editor Upgrade
- Phone homepage preview now looks like an actual phone, including device frame/notch/status area.
- Phone landing crop no longer uses a movable/resizable crop rectangle.
- Phone mode uses a fixed phone-shaped viewport; the user drags the photo behind it and adjusts zoom with one slider.
- Desktop crop workflow remains box-based.
- Fit Entire Photo / Black Bars remains available.
- Saved crop data format is unchanged, so no D1 migration or Worker update is required.

## V15.2 Mobile Homepage Polish
- Public phone homepage now uses a full-bleed landing photo instead of a picture floating in a large black hero.
- Normal saved phone crops fill the mobile hero edge-to-edge.
- Full-photo crops (Fit Entire Photo / Black Bars) still preserve the entire image with bars when intentionally selected.
- Mobile hero branding is smaller and anchored near the bottom over a controlled vertical gradient.
- Category cards flow naturally below the hero.
- Visual Editor phone preview follows the same full-bleed behavior.
- No D1 or Worker update required.

## V15.3 Dual-Device Editor
- Landing Slideshow now shows Desktop and Phone crops side-by-side for the same photo.
- Desktop and Phone crops save independently.
- Separate Exclude on Desktop / Exclude on Phone checkboxes are stored in each device's existing crop JSON.
- Editor UI changes do not normalize, rewrite, or reset previously saved crop values on load.
- Individual photos can be uploaded directly from Landing Slideshow; they are added to the chosen portfolio category and then to Landing Slideshow.
- Portfolio category tabs retain direct individual-photo uploads.
- Recent Shoots and Recent Gallery Editor retain direct individual-photo uploads.
- Main Admin full-folder uploader is preserved unchanged.
- No schema/data migration and no Worker update required.

## V15.4 Continuous Phone Framing
- Removes the binary jump between Fit Entire Photo and Fill Screen.
- Phone framing slider now runs continuously:
  0 = Fit Entire Photo,
  1–99 = progressively reduce black bars,
  100 = Fill Screen,
  101–200 = extra zoom beyond Fill.
- Drag-to-reposition works at every framing level.
- Public homepage and Visual Editor render the exact saved phone crop with containment, so intermediate framing is preserved instead of being forced to Fill.
- Existing x/y/w/h crop data is read as-is and mapped to the closest slider position.
- No crop data is rewritten on load.
- No D1 migration or Worker update required.

## V15.6 Crop Repair + Sticky Public Navigation
- Rebuilt from V15.4, the last intact dual-device crop version.
- Restores Desktop drag/resize and Phone drag/framing-slider controls.
- Adds Show Text Overlay independently to Desktop and Phone previews.
- Uses one SAVE BOTH DEVICE CROPS button; Ctrl+S also saves both.
- Overlay toggles are preview-only and never write crop data.
- Existing saved crops are read as-is and are not rewritten on load.
- Public site header is sticky/docked at the top on public pages.
- Replaces the small Instagram glyph with a larger recognizable Instagram icon and an Instagram text label.
- No D1 migration or Worker update required.

## V16 Reels
Marketing-only Reels feature.

Deployment order:
1. D1 Migration V8 (creates a new reels table only).
2. Worker V8.
3. Website V16.

Features:
- Public Reels page.
- Reels link in public sticky navigation.
- Reels tab in Visual Editor.
- Direct MP4/WebM upload.
- Browser-generated poster frame when supported.
- Title, caption, sport, team, event/game and optional related Recent Shoot.
- Public show/hide, ordering and permanent delete.
- Optional link from a Reel to its related photo shoot.
- Videos live in the existing private ORIGINALS R2 bucket and stream through the Worker.
- Poster frames live in PREVIEWS.
- Reels are not connected to cart, orders, print pricing, or digital sales.

Data safety:
- No existing table is altered by V8.
- No existing crop, portfolio, slideshow, gallery, pricing or order data is rewritten.

## V17 Athletes + Fan Favorites
- Adds Athletes tab to Visual Editor.
- Admin can create verified athlete records, add sport/team memberships, and add multiple jersey numbers.
- Adds pending photo-claim review queue (approve/reject).
- Public Recent Shoot galleries get 1–5 star rating UI.
- Ratings explicitly explain they contribute to public Fan Favorites and are separate from private Favorites.
- Adds event-level Fan Favorites section ranked by average rating then rating count.
- Does not enable player login/self-claiming yet; authentication is intentionally deferred.
- No D1 migration beyond already-completed V9 and no Worker change beyond already-deployed V9.
- Existing crops, reels, slideshow, pricing, orders and gallery records are not modified by this website deployment.

## V18 - General Tags + Player Login / My Photos
- Adds general photo/gallery tagging UI in Visual Editor.
- Tag types: person, product, team, sport, event, location, subject, custom.
- Ordinary person tags remain descriptive only and do not grant athlete privileges.
- Adds Player Login / My Photos page with registration/login and verified person search.
- Search supports first name, last name, full/partial name, jersey, and general tags.
- Adds “That's Me” claims on Recent Shoot photos for verified athletes.
- Adds inline My Events panel on a current event so players can see and preview approved photos from other events without leaving the page.
- Allows selecting multiple existing events in preparation for one checkout; does not advertise a future-event or bundle discount.
- Adds admin review UI for athlete profile requests.
- Fixes V17 ratings by attaching actual D1 photo IDs to event photo cards.
- Existing crop, Reel, slideshow, pricing and order data are not rewritten.

## V19 - Player / Client roles and mobile UX
- Renames public Player Login to Player / Client Login.
- Signup supports Player, Parent / Guardian, Client, and Other; multiple roles can be selected.
- Sports are multi-select: baseball, football, lacrosse, soccer, track, pool, other.
- Jersey input accepts spaces/commas/semicolons and previews/asks for confirmation when multiple values are detected.
- Adds Accounts / Clients tab in Visual Editor.
- Admin can grant or revoke per-gallery client entitlements for all digital originals and/or print ordering.
- Client account page displays entitled galleries and granted access.
- Mobile menu closes after a navigation choice, outside tap, Escape, or about 3 seconds.
- Mobile forms use larger touch targets and simplified responsive layouts.

## V19.1 - Simplified login entry
- First Player / Client page now shows only two choices: Login or Create New Account.
- Login panel contains only email and password.
- Unknown email receives a Yes / No create-account prompt.
- Yes opens registration with the attempted email already filled in.
- Registration remains role-aware and mobile friendly.

## V20 - Reports / Activity + Notifications + Account Controls
- Adds Reports / Activity tab to Visual Editor.
- Current month default plus Today, Last 7 Days, Last Month, This Year, and custom range.
- Adds Admin Notification Email settings and alert toggles.
- Adds account Deactivate, Reactivate, and Delete controls.
- Delete uses backend purchase-history protection.
- Adds logged-in notification badge and New Since Your Last Login panel.
- Adds Mark All Read.
- Purchase/revenue report fields are ready but remain zero until Stripe records verified purchases.
- Outbound email sending still awaits email-provider integration.

## V20.1 - Find a Shoot Search
- Find a Shoot searches the Worker metadata endpoint, not only gallery titles.
- Supports verified person/player names (first, last, full, partial), jersey number, team, sport, general person/product/location/subject/event/custom tags, gallery tags, shoot title, and date.
- Search results display directly below the finder.
- Result cards explain why a shoot matched and show matching-photo counts when available.
- No-query view still shows the normal Recent Shoots list.
- Mobile layout uses one prominent search field with large touch targets.

## V21
- Admin Rosters tab with school/team/sport/season.
- Add/edit/remove roster players and jersey numbers.
- Assign rosters to galleries.
- Gallery-level Tag a Player workflow for anyone.
- Autocomplete ranks current gallery roster first but shows matches from other rosters/schools/sports.
- Multiple same-name players remain visually distinct.
- Unlisted player suggestions are allowed and stay unverified.
- Select multiple photos and submit the player tag once.
- Admin and verified-player approval interfaces.
- Fan Favorites rating moved above purchase controls on each gallery photo.

## V21.1
- Tagging instructions explicitly explain selecting multiple photos before submitting.
- Tagging panel docks and highlights red while tagging mode is active.
- Gallery lightbox/photo expansion is disabled while tagging.
- Each selected photo gets a strong selected state.
- Public autocomplete result source distinguishes gallery roster / other roster / existing verified player.
- Submission passes roster ID, athlete ID, jersey number and name to Worker V15.1.
- After a successful submit, tagging mode remains active so another player can be tagged on the same photos.
- Existing verified and pending player tags are shown on each photo above Fan Favorites.
- Multiple player tags display on the same photo.
- Clicking the same Fan Favorites star rating again clears the user's rating to 0.
- Digital pricing display updated: $10 single, Any 3 $25, All Photos of One Player $35.
- $35 player package is labeled per player/per event and excludes team/group photos.
- Cart automatically prices Any 3 at $25 and single digitals at $10.
- Fan Favorite free-prize concept is NOT implemented; it remains an idea only.

## V21.2
- Successful player-tag submission now automatically exits red tagging mode.
- A brief normal-state confirmation appears after submission.
- Pending player labels render as "Player Name — Unverified".
- Once approved, the same label renders as only "Player Name".
- Multiple player tags remain supported on the same photo.
- Reels API and video media requests use fresh cache-busting query strings.
- Reel playback automatically retries once with a new URL after a media error.
- This targets cases where a normal browser has a stale/partial cached reel while Incognito works.

## V21.3
- Removes the bordered Player / Client Login box from gallery pages.
- Adds a red Player / Client Login button aligned right directly above Tag a Player.
- Adds the same cleaner red login treatment to Recent Shoots.
- Successful tag submission always exits active/red tagging mode.
- Pending tag appears immediately beneath the photo above Fan Favorites as "Player Name — Unverified".
- API refresh replaces pending label with simply "Player Name" after approval.
- Multiple different players remain supported on one photo.

## V21.3.1 gallery photo hotfix
- Restores loadPhotoPlayerTags(), accidentally removed in V21.3.
- Prevents optional tagging/player helpers from stopping the gallery photo grid.
- Keeps V21.3 login layout and tag-label behavior.
- Does not alter gallery data, R2 files, D1 records, crops, or uploads.

## V21.3.2 batch tag submit
- Uses Worker V15.3 gallery-level batch player-tag endpoint.
- All selected photos are submitted in one request.
- Successful submit exits red tagging mode.
- Pending labels appear immediately as "Player Name — Unverified".
- Approved labels remain simply "Player Name" after refresh.
- If the API fails, the real error message is shown and selected photos stay selected.
- Preserves V21.3.1 gallery rendering hotfix.

## V21.3.3 no-preflight player tag submit
- Changes public gallery player-tag POST from application/json to text/plain.
- Body remains JSON and Worker V15.3 continues to parse it with request.json().
- Avoids browser CORS preflight for this public submission route.
- Preserves V21.3.1 gallery photo hotfix and all V21.3.2 batch-tag behavior.

## V21.4 Gallery Search Navigator
- Carries q= search into gallery links from Find a Shoot where supported.
- Adds Search This Gallery input and Clear Search.
- Worker V15.7 returns exact matching photo IDs and reasons.
- Matching photos stay full brightness and receive MATCH badges/red outline.
- Non-matches remain visible but are dimmed.
- Sticky navigator shows total matching photos and Match X of X.
- Shows approximate "Next match X photos down" status.
- Previous / Next buttons jump between results.
- Red tick marks across the search map show where matches sit in the gallery.
- Scroll updates the current match automatically.

## V21.4.1 Search Carryover + Simplified Navigator
- Fixes Recent Shoots search links so the active q= search is carried into the opened gallery.
- The gallery automatically runs that same search after loading.
- Removes the unintuitive red tick-map representation.
- Replaces it with a large "current / total" result indicator.
- Shows plain-language remaining-result status such as "3 more matches below".
- Keeps Previous Match / Next Match controls.
- Keeps matching cards bright/red and non-matches dimmed.

## V21.4.2 Visible Search Matches
- Recent Shoots displays the actual names/terms that caused the galleries to match.
- Partial searches such as "E" can visibly show Evan Henry, Ethan Brooks, Earl Johnson, etc.
- Match names are clickable chips; clicking one narrows the search immediately.
- The same Matches Found row appears inside the gallery.
- Existing search carryover, highlighted matches, dimmed non-matches, result counter, and Previous/Next remain unchanged.

## V21.5 Stripe Sandbox Checkout
- Cart now calls POST /api/checkout/session.
- Redirects customers to Stripe-hosted Checkout.
- Uses Worker-side pricing; browser price values are not trusted.
- Stripe secret remains server-side in Cloudflare.
- Cart remains intact after success until webhook/D1 paid-order persistence is implemented.
- Success and cancel returns are displayed on cart.html.
- Test mode wording is explicit.

## V21.5.1 Address Line 2 Optional
- Keeps shipping fields required for print orders.
- Address Line 2 is always optional.
- Stripe sandbox checkout flow is unchanged.

## V21.6 Order Confirmed
- Successful Stripe returns now route to order-confirmation.html.
- Confirmation page verifies the Stripe session against the Worker/D1 order.
- Shows order number, paid status, item summary, subtotal, discounts, shipping, tax, and total.
- Handles webhook timing by polling briefly while an order is still being finalized.
- Cart clears only after a confirmed paid D1 order is returned.
- Cancelled Stripe Checkout continues to return to the cart without clearing it.
- Current sandbox fulfillment note explicitly says automatic delivery/Prodigi fulfillment is not live yet.

## V21.6.1 Secure Digital Delivery UI
- Paid digital items show a Download High-Resolution File button.
- Buttons use secure Worker-issued download URLs and do not expose R2 object keys.
- Displays the entitlement expiration date.
- Digital-only orders now state that the purchased photo is ready immediately.

## V21.7 Stripe Embedded Checkout
- Uses Stripe Embedded Checkout inside cart.html instead of redirecting to a Stripe-hosted page.
- Calls POST /api/checkout/embedded-session.
- Uses Stripe.js directly from js.stripe.com.
- Existing webhook, D1 paid-order recording, Order Confirmed page, and secure digital delivery remain intact.
- Shipping address is collected inside Stripe for print orders.
- Includes a Back button to leave the embedded payment form before completing payment.

## V21.8 Prodigi Dynamic Shipping
- Adds Stripe Embedded Checkout `onShippingDetailsChange`.
- Print customers enter a U.S. shipping address inside Stripe.
- The browser calls `/api/checkout/shipping-quote`.
- The Worker asks Prodigi Sandbox for Budget shipping, requires USD and U.S. fulfillment, then updates the Stripe Checkout Session.
- Stripe accepts the shipping details only after the Worker succeeds.
- No Prodigi order is created by this website version.

## V21.8.1 Prodigi Confirmation Status
- Print orders with `fulfillment_status=submitted` now say the order has been sent to the print lab.
- Failed fulfillment shows a review message instead of a false success message.
- Mixed digital + print orders preserve the secure download message and add the print-lab status.

## V21.8.2 Checkout Guidance
- Adds a red left-column instruction panel: press Continue to calculate shipping/tax, then scroll and Pay.
- Automatically scrolls to the Embedded Checkout when it opens.
- Adds a sticky red "Scroll down to Continue / Pay" cue above Stripe.
- Makes the site-side order summary sticky on desktop.
- Site-side shipping summary updates to the actual Prodigi quote after Continue.
- Mobile leaves the order summary non-sticky to preserve screen space.


## V21.9 Navigation / Portfolio / Recent Events Redesign
- Homepage now presents three clear visitor goals:
  - Portfolio Samples / View My Work
  - Recent Events / Find Your Photos
  - Other Work for Sale / Shop Photography
- Homepage photo tiles retain crop control by mapping to existing Visual Editor cover sources.
- Public navigation wording changes Recent Shoots -> Recent Events without breaking old URLs.
- Portfolio uses docked All / Sports / Portraits / Events / Other filters.
- Single click on an enlarged photo closes the lightbox.
- Desktop lightbox keeps the purchase panel permanently open; mobile keeps the expandable panel.
- Recent Events folder rail stays horizontal and scrolls left/right when needed.
- Gallery package banner contains a smaller Player / Client Login button on the right.
- Tag a Player is the primary sticky tool and explicitly says "Tag multiple photos at once."
- Gallery Search becomes sticky only while search results are active.
- Existing player tags continue to render below each photo through the existing tag API/UI.
- Recent Event cards use the new saved cover photo + desktop/mobile crop fields.
- Recent Gallery Editor adds cover-photo selection plus visual Desktop/Phone crop preview controls.
- Visual Editor homepage preview now shows the three new purpose cards and retains Edit Photo / Crop.


## V21.9.1
- Homepage photo links simplified to red kicker + white title only.
- Removed duplicate descriptions and secondary Browse/Find/View buttons.
- Text is positioned lower in each homepage photo.
- Portfolio title and All/Sports/Portraits/Events/Other controls are docked together.
- Recent Events loading made defensive:
  - uses saved event cover when available
  - otherwise uses first gallery photo
  - a missing crop can no longer blank a card
  - individual gallery-detail failures no longer hide all events
- Existing cover crop controls remain supported.

## V21.9.2
- Homepage purpose-card red rules are left aligned directly under the text.

## V21.10
- Public player tags are fetched from the public gallery player-tag API and shown beneath every tagged photo for all visitors, logged in or not.
- Both verified and pending/unverified tags are shown.
- Zoomed sale photos include Tag This Photo; it opens tagging mode with that photo already selected.
- Long tagging instructions are hidden until multi-photo tagging mode is active.
- Gallery search navigator is hidden unless a search is active.
- Fan Favorites stars are centered; helper text about clearing to zero was removed while repeat-click-to-zero remains functional.
- Portfolio removes All and keeps Sports / Portraits / Events / Other in a smaller elegant centered sticky dock.

## V21.10.1
- Zoom-view "Tag This Photo" moved above the purchase controls.
- Styled as a compact red secondary action at roughly half the width of Add to Cart.
- Prevents the tag control from dominating or obscuring purchase information.
