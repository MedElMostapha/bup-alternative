import { useEffect, useRef } from "react";
import { defaultKeymap, history, historyKeymap } from "@codemirror/commands";
import { highlightSelectionMatches, search, searchKeymap } from "@codemirror/search";
import { EditorState, RangeSetBuilder } from "@codemirror/state";
import {
  Decoration,
  type DecorationSet,
  EditorView,
  highlightSpecialChars,
  keymap,
  lineNumbers,
  ViewPlugin,
  type ViewUpdate,
} from "@codemirror/view";

const MARKER = "§";
const HEAD_LINE_LIMIT = 400;

const headerName = Decoration.mark({ class: "cm-http-name" });
const startLine = Decoration.mark({ class: "cm-http-start" });
const position = Decoration.mark({ class: "cm-http-position" });

function buildDecorations(view: EditorView): DecorationSet {
  const { doc } = view.state;
  let headEnd = 0;
  while (headEnd < Math.min(doc.lines, HEAD_LINE_LIMIT)) {
    if (doc.line(headEnd + 1).text.replace(/\r$/, "") === "") break;
    headEnd += 1;
  }
  const builder = new RangeSetBuilder<Decoration>();
  for (const { from, to } of view.visibleRanges) {
    let pos = from;
    while (pos <= to) {
      const line = doc.lineAt(pos);
      const marks: Array<[number, number, Decoration]> = [];
      if (line.number === 1) {
        marks.push([line.from, line.to, startLine]);
      } else if (line.number <= headEnd) {
        const colon = line.text.indexOf(":");
        if (colon > 0) marks.push([line.from, line.from + colon, headerName]);
      }
      // Pair the markers within the line so whole positions are tinted.
      let open = line.text.indexOf(MARKER);
      while (open !== -1) {
        const close = line.text.indexOf(MARKER, open + 1);
        if (close === -1) break;
        marks.push([line.from + open, line.from + close + 1, position]);
        open = line.text.indexOf(MARKER, close + 1);
      }
      marks.sort((a, b) => a[0] - b[0]);
      let last = -1;
      for (const [start, end, mark] of marks) {
        // A position inside the start line would overlap its highlight.
        if (start >= last) {
          builder.add(start, end, mark);
          last = end;
        }
      }
      pos = line.to + 1;
    }
  }
  return builder.finish();
}

const httpHighlight = ViewPlugin.fromClass(
  class {
    decorations: DecorationSet;
    constructor(view: EditorView) {
      this.decorations = buildDecorations(view);
    }
    update(update: ViewUpdate) {
      if (update.docChanged || update.viewportChanged) this.decorations = buildDecorations(update.view);
    }
  },
  { decorations: (plugin) => plugin.decorations },
);

const theme = EditorView.theme({
  "&": { height: "100%", fontSize: "12.5px", backgroundColor: "var(--surface)", color: "var(--text)" },
  "&.cm-focused": { outline: "none" },
  ".cm-scroller": { fontFamily: "var(--mono)", lineHeight: "1.55" },
  ".cm-content": { caretColor: "var(--accent)" },
  ".cm-cursor": { borderLeftColor: "var(--accent)" },
  ".cm-gutters": { backgroundColor: "var(--surface)", color: "var(--faint)", border: "none" },
  ".cm-selectionBackground, &.cm-focused .cm-selectionBackground": { backgroundColor: "var(--selection) !important" },
  ".cm-selectionMatch": { backgroundColor: "var(--selection)" },
  ".cm-http-name": { color: "var(--accent-text)" },
  ".cm-http-start": { fontWeight: "600" },
  ".cm-http-position": { backgroundColor: "var(--marker-bg)", color: "var(--marker-text)", borderRadius: "2px" },
  ".cm-panels": { backgroundColor: "var(--raised)", color: "var(--text)", borderColor: "var(--border)" },
});

/** Actions a parent can perform on the current selection. */
export interface RawEditorHandle {
  markSelection: () => void;
}

interface Props {
  value: string;
  onChange?: (value: string) => void;
  readOnly?: boolean;
  handleRef?: React.RefObject<RawEditorHandle | null>;
}

export function RawEditor({ value, onChange, readOnly = false, handleRef }: Props) {
  const host = useRef<HTMLDivElement>(null);
  const view = useRef<EditorView | null>(null);
  const changeHandler = useRef(onChange);
  changeHandler.current = onChange;

  useEffect(() => {
    const editor = new EditorView({
      parent: host.current!,
      state: EditorState.create({
        doc: value,
        extensions: [
          // CR must stay in the text: without this the editor would rewrite
          // every CRLF as LF and change the message being edited.
          EditorState.lineSeparator.of("\n"),
          EditorState.readOnly.of(readOnly),
          EditorView.editable.of(!readOnly),
          lineNumbers(),
          history(),
          search(),
          highlightSelectionMatches(),
          highlightSpecialChars({
            render: (code, _description, placeholder) => {
              if (code === 13) return document.createElement("span");
              const mark = document.createElement("span");
              mark.className = "cm-specialChar";
              mark.textContent = placeholder;
              return mark;
            },
          }),
          keymap.of([...defaultKeymap, ...historyKeymap, ...searchKeymap]),
          EditorView.lineWrapping,
          httpHighlight,
          theme,
          EditorView.updateListener.of((update) => {
            if (update.docChanged) changeHandler.current?.(update.state.doc.toString());
          }),
        ],
      }),
    });
    view.current = editor;
    return () => editor.destroy();
    // The editor is created once; value changes are applied below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [readOnly]);

  useEffect(() => {
    const editor = view.current;
    if (editor && editor.state.doc.toString() !== value) {
      editor.dispatch({ changes: { from: 0, to: editor.state.doc.length, insert: value } });
    }
  }, [value]);

  useEffect(() => {
    if (!handleRef) return;
    handleRef.current = {
      markSelection: () => {
        const editor = view.current;
        if (!editor) return;
        const { from, to } = editor.state.selection.main;
        editor.dispatch({
          changes: [
            { from, insert: MARKER },
            { from: to, insert: MARKER },
          ],
        });
        editor.focus();
      },
    };
  }, [handleRef]);

  return <div className="editor" ref={host} />;
}
