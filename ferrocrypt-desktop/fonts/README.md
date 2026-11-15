# Fonts

The desktop app embeds these fonts in its binary (`ui/app.slint` imports them).

- `Inter-Regular.ttf`, `Inter-SemiBold.ttf`, `Inter-Bold.ttf`: Inter 4.1,
  unchanged, from `extras/ttf/` in `Inter-4.1.zip` of the
  [v4.1 release](https://github.com/rsms/inter/releases/tag/v4.1). Licensed
  under the SIL Open Font License 1.1: `OFL.txt` is the release's
  `LICENSE.txt`.
- `PasswordMask.ttf`: a smaller "●" for masked passwords, with Inter's line
  metrics. Built by `scripts/make_password_mask_font.py`, which reads those
  metrics from `Inter-Regular.ttf`: line heights, x-height and cap height,
  weight class, and style flags. It takes no outlines from Inter. Licensed
  under GPL-3.0-only, as the rest of FerroCrypt.

SHA-256:

```
9883fdd4a49d4fb66bd8177ba6625ef9a64aa45899767dde3d36aa425756b11e  Inter-4.1.zip
40d692fce188e4471e2b3cba937be967878f631ad3ebbbdcd587687c7ebe0c82  Inter-Regular.ttf
78a843fade9d4612a5567302fb595b56976eb5fcebf4fea5a5912d638bafcde3  Inter-SemiBold.ttf
288316099b1e0a47a4716d159098005eef7c0066921f34e3200393dbdb01947f  Inter-Bold.ttf
```
