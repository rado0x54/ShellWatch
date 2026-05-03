<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<div class="placeholder-page">
  <div class="placeholder-inner">
    <div class="placeholder-logo" aria-hidden="true"></div>
    <p>Select an endpoint or session from the sidebar</p>
  </div>
</div>

<style>
  .placeholder-page {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: var(--space-5);
    background: var(--surface-dim);
  }

  .placeholder-inner {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-5);
    max-width: 28rem;
    color: var(--on-surface-faint);
    font-family: var(--font-mono);
    font-size: var(--label-md);
    text-transform: uppercase;
    letter-spacing: 0.14em;
    text-align: center;
  }

  .placeholder-logo {
    width: 128px;
    height: 128px;
    background: currentColor;
    mask: url("/logo.svg") center / contain no-repeat;
    -webkit-mask: url("/logo.svg") center / contain no-repeat;
  }
</style>
