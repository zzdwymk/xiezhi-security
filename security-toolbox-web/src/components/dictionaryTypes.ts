export interface DictionaryView {
  source: string;
  wordCount: number;
}

export interface DictionaryWordPage {
  words: string[];
  page: number;
  size: number;
  total: number;
}

export interface DictionaryImportResult {
  imported: number;
  invalid: number;
  duplicates: number;
  issues: string[];
}

export interface DictionaryUpdateResult {
  view: DictionaryView;
  added: number;
  removed: number;
  missing: string[];
}

export interface DictionaryApi {
  view: () => Promise<DictionaryView>;
  words: (query: string, page: number, size: number) => Promise<DictionaryWordPage>;
  importText: (text: string) => Promise<DictionaryImportResult>;
  update: (
    additions: string[],
    removals: string[],
  ) => Promise<DictionaryUpdateResult>;
}
