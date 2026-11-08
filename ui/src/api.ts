import type { UiEvent } from "./types";

type Backend = typeof import("./backend-tauri");

function loadBackend(): Promise<Backend> {
  if (import.meta.env.DEV && !("__TAURI_INTERNALS__" in window)) {
    return import("./backend-mock") as unknown as Promise<Backend>;
  }
  return import("./backend-tauri");
}

const backend = loadBackend();

export async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  return (await backend).invoke<T>(command, args);
}

export const dialogs = {
  file: async () => (await backend).chooseFile(),
  project: async () => (await backend).chooseProject(),
  newProject: async () => (await backend).chooseNewProject(),
  certPath: async () => (await backend).chooseCertPath(),
};

type Listener = (events: UiEvent[]) => void;
const listeners = new Set<Listener>();

void backend.then((b) => b.listen((events) => listeners.forEach((listener) => listener(events))));

export function subscribe(listener: Listener): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

type ToastListener = (message: string) => void;
const toastListeners = new Set<ToastListener>();

export function toast(message: unknown): void {
  toastListeners.forEach((listener) => listener(String(message)));
}

export function subscribeToasts(listener: ToastListener): () => void {
  toastListeners.add(listener);
  return () => toastListeners.delete(listener);
}
