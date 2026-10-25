# ZCrypt brand

One identity across the website, the desktop wallet and the phone wallet. This folder is
the source of truth; the website shows it at https://zcrypt.network/#brand.

## The mark

The mark is the letter Z drawn as a single stroke with round ends: two bars joined by a
diagonal. It is never redrawn, outlined, skewed or given a drop shadow.

| File | Use |
| --- | --- |
| `logo-mark.svg` | The stroke alone. Takes its colour from `currentColor`. Headers, inline, monochrome. |
| `logo-tile.svg` | The mark in ink on the signal gradient, 27.5% corner radius. Avatars, app icons on desktop. |
| `logo-tile-square.svg` | Same without the corner radius, for platforms that mask icons themselves (iOS, Android). |
| `favicon.svg` | The mark in cyan on ink. Favicons and small dark-background uses. |
| `logo-lockup.svg` | Tile plus wordmark for places that need a single image. In HTML, set the wordmark as live text. |
| `png/` | Rendered sizes: 1024 (app icon source), 512, 192, 180 (Apple touch), 32 and 16. |

Clear space around the mark is one bar-height on every side. Minimum size is 16 px.

### Wordmark

"ZCrypt": capital Z, capital C, the rest lowercase. Inter Tight, weight 600, tracking
-0.02em, in `--zc-text`. The network is "zcrypt-1" in mono. The coin is "ZCRYPT" in
capitals. Never "Zcrypt" or "ZCRYPT wallet".

## Colour

Everything sits on ink (`#06080f`). One signal colour, cyan `#35e0ff`, carries links,
primary actions and the mark; the gradient to violet `#6d7cff` is for the tile, hero
buttons and balance cards, not for text. Green, amber and red mean ok, warning and
failure, and nothing else. See `tokens.css` for the full set.

## Type

- **Inter Tight** for everything: display at -0.04em, titles at -0.02em, body at 16px/1.5.
- **Instrument Serif italic** on the website only, for the one emphasised phrase in a
  heading. Never in the apps.
- **JetBrains Mono** for hashes, addresses, amounts in tables, block heights and code.
  Uppercase labels are mono at 0.74rem with 0.08em tracking.

The website loads the faces from Google Fonts. The apps bundle the latin subsets in
`fonts/` through `fonts.css`, so they render offline and identically on every platform.

## Shape and motion

Cards, sheets and buttons use 18px radius; inputs and chips 12px; pills 999px. Motion uses
`--zc-ease` and respects reduced-motion settings. Cyan glow (`--zc-glow`) is reserved for
the tile and the balance hero.

## Where it is applied

| Surface | Files |
| --- | --- |
| Website | `brand/` copy, `site.css` tokens, `index.html#brand` section |
| Desktop wallet | `wallet/src/brand/`, `wallet/src/App.css` |
| Phone wallet | `wallet/src/brand/`, `wallet/src/mobile/mobile.css`, `Logo` in `wallet/src/mobile/ui.tsx` |
| App icons | `npx tauri icon brand/png/logo-tile-1024.png --ios-color "#06080f"` from `wallet/` |

To change a token: edit `brand/tokens.css`, run `brand/sync.sh`, and rebuild.
