// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { redirect } from "@sveltejs/kit";

export function load() {
  redirect(307, "/audit/sessions");
}
