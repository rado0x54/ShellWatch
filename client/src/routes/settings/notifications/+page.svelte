<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  import { onMount } from "svelte";
  import { toastError, toastInfo } from "$lib/stores/toasts.js";
  import { errorMessage } from "$lib/utils/error-message.js";
  import {
    pushSupported,
    pushEnabled,
    pushLoading,
    vapidAvailable,
    checkPushStatus,
    subscribePush,
    unsubscribePush,
  } from "$lib/stores/push.js";

  let vapidConfigured = $state(false);
  let permissionState = $state<"default" | "granted" | "denied">("default");

  onMount(async () => {
    vapidConfigured = vapidAvailable();
    if (pushSupported) {
      permissionState = Notification.permission;
      await checkPushStatus();
    }
  });

  async function handleToggle() {
    if ($pushEnabled) {
      try {
        await unsubscribePush();
        toastInfo("Push notifications disabled");
      } catch (err) {
        toastError(errorMessage(err));
      }
    } else {
      try {
        await subscribePush();
        permissionState = Notification.permission;
        toastInfo("Push notifications enabled");
      } catch (err) {
        permissionState = Notification.permission;
        if (permissionState === "denied") {
          toastError(
            "Notification permission denied. Please allow notifications in browser settings.",
          );
        } else {
          toastError(errorMessage(err));
        }
      }
    }
  }
</script>

<section>
  <h2>Push Notifications</h2>

  {#if !pushSupported}
    <div class="info-box">Push notifications are not supported in this browser.</div>
  {:else if !vapidConfigured}
    <div class="info-box">
      Push notifications are not configured on this server. Add a <code>vapid</code> section to your
      <code>config.yaml</code> to enable them.
    </div>
  {:else}
    <div class="settings-section">
      <div class="field">
        <label for="push-toggle">Push Notifications</label>
        <div class="toggle-row">
          <button
            type="button"
            id="push-toggle"
            class="toggle"
            class:active={$pushEnabled}
            disabled={$pushLoading}
            onclick={handleToggle}
            aria-label="Push Notifications"
            role="switch"
            aria-checked={$pushEnabled}
          >
            <span class="toggle-knob"></span>
          </button>
          <span class="toggle-label">
            {#if $pushLoading}
              Updating...
            {:else if $pushEnabled}
              Enabled
            {:else}
              Disabled
            {/if}
          </span>
        </div>
        <span class="field-hint">
          Receive push notifications for sign requests (passkey signing, SSH key approval) even when
          this tab is closed.
        </span>
      </div>

      {#if permissionState === "denied"}
        <div class="info-box info-box-warn">
          Notification permission is blocked. To enable push notifications, update your browser's
          notification settings for this site.
        </div>
      {/if}
    </div>
  {/if}
</section>

<style>
  h2 {
    font-size: 0.75rem;
    font-weight: 600;
    margin-bottom: 0.75rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .settings-section {
    max-width: 480px;
  }

  .field {
    margin-bottom: 1rem;
  }

  .field label {
    display: block;
    font-size: 0.8rem;
    font-weight: 500;
    margin-bottom: 0.375rem;
    color: var(--text-muted);
  }

  .toggle-row {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }

  .toggle {
    position: relative;
    width: 40px;
    height: 22px;
    border-radius: 11px;
    border: 1px solid var(--border);
    background: var(--bg-primary);
    cursor: pointer;
    padding: 0;
    transition: background-color 0.2s;
  }

  .toggle.active {
    background: var(--green, #4ade80);
    border-color: var(--green, #4ade80);
  }

  .toggle-knob {
    position: absolute;
    top: 2px;
    left: 2px;
    width: 16px;
    height: 16px;
    border-radius: 50%;
    background: var(--text-muted);
    transition:
      transform 0.2s,
      background-color 0.2s;
  }

  .toggle.active .toggle-knob {
    transform: translateX(18px);
    background: white;
  }

  .toggle-label {
    font-size: 0.85rem;
    color: var(--text-primary);
  }

  .field-hint {
    display: block;
    font-size: 0.75rem;
    color: var(--text-muted);
    margin-top: 0.375rem;
  }

  .info-box {
    padding: 0.75rem 1rem;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 6px;
    font-size: 0.8rem;
    color: var(--text-muted);
    max-width: 480px;
  }

  .info-box-warn {
    border-color: var(--red);
    color: var(--red);
  }

  .info-box code {
    background: var(--bg-secondary);
    padding: 0.1rem 0.3rem;
    border-radius: 3px;
    font-size: 0.75rem;
  }
</style>
