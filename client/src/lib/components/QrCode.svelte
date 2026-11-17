<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  // QR code as an inline SVG path (no innerHTML): one square per dark module.
  import qrcode from "qrcode-generator";

  interface Props {
    value: string;
    size?: number;
  }

  let { value, size = 200 }: Props = $props();

  const model = $derived.by(() => {
    const qr = qrcode(0, "M");
    qr.addData(value);
    qr.make();
    const n = qr.getModuleCount();
    let d = "";
    for (let r = 0; r < n; r++) {
      for (let c = 0; c < n; c++) {
        if (qr.isDark(r, c)) d += `M${c + 4} ${r + 4}h1v1h-1z`;
      }
    }
    return { d, dim: n + 8 };
  });
</script>

<svg
  class="qr"
  width={size}
  height={size}
  viewBox="0 0 {model.dim} {model.dim}"
  shape-rendering="crispEdges"
  role="img"
  aria-label="QR code of the access link"
>
  <rect width={model.dim} height={model.dim} fill="#fff" />
  <path d={model.d} fill="#000" />
</svg>

<style>
  .qr {
    display: block;
    border-radius: 4px;
  }
</style>
