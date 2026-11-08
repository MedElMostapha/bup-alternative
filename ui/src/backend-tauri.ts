import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { listen as tauriListen } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";
import type { UiEvent } from "./types";

export const invoke = tauriInvoke;

export async function listen(handler: (events: UiEvent[]) => void): Promise<void> {
  await tauriListen<UiEvent[]>("sluice-events", (event) => handler(event.payload));
}

const PROJECT_FILTER = [{ name: "Sluice project", extensions: ["sluice"] }];

export async function chooseFile(): Promise<string | null> {
  const picked = await open({ multiple: false, directory: false });
  return typeof picked === "string" ? picked : null;
}

export async function chooseProject(): Promise<string | null> {
  const picked = await open({ multiple: false, directory: false, filters: PROJECT_FILTER });
  return typeof picked === "string" ? picked : null;
}

export async function chooseNewProject(): Promise<string | null> {
  return save({ defaultPath: "project.sluice", filters: PROJECT_FILTER });
}

export async function chooseCertPath(): Promise<string | null> {
  return save({ defaultPath: "sluice-ca.pem", filters: [{ name: "Certificate", extensions: ["pem"] }] });
}
