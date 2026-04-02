<script lang="ts">
  interface Props {
    uuid: string;
    size?: number;
  }

  let { uuid, size = 36 }: Props = $props();

  // Generate a deterministic 5x5 symmetric pattern from UUID hex digits
  function generate(id: string): { cells: boolean[][]; hue: number } {
    const hex = id.replace(/-/g, "");
    const cells: boolean[][] = [];

    // Use first 2 hex chars for hue (0-255 → 0-360)
    const hue = (parseInt(hex.slice(0, 2), 16) / 255) * 360;

    // 5x5 grid, vertically symmetric — only need 3 columns (left half + center)
    // Each row needs 3 bits, 5 rows = 15 bits = ~4 hex chars
    for (let row = 0; row < 5; row++) {
      cells[row] = [];
      for (let col = 0; col < 5; col++) {
        // Mirror: col 0=4, 1=3, 2=center
        const mirrorCol = col > 2 ? 4 - col : col;
        const idx = row * 3 + mirrorCol;
        // Use hex chars starting from position 2 (after hue)
        const hexChar = parseInt(hex[idx + 2], 16);
        cells[row][col] = hexChar > 7;
      }
    }

    return { cells, hue };
  }

  const pattern = $derived(generate(uuid));
  const cellSize = $derived(size / 7); // 5 cells + 1 padding each side
  const padding = $derived(cellSize);
</script>

<svg width={size} height={size} viewBox="0 0 {size} {size}" role="img" aria-label="Account avatar">
  <rect width={size} height={size} rx="4" fill="hsl({pattern.hue}, 30%, 15%)" />
  {#each pattern.cells as row, y (y)}
    {#each row as filled, x (x)}
      {#if filled}
        <rect
          x={padding + x * cellSize}
          y={padding + y * cellSize}
          width={cellSize}
          height={cellSize}
          rx="1"
          fill="hsl({pattern.hue}, 60%, 55%)"
        />
      {/if}
    {/each}
  {/each}
</svg>
