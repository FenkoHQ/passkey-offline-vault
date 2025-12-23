/**
 * Import Page for PassKey Vault
 *
 * Handles importing passkeys from backup files
 */

(function () {
  'use strict';

  const IMPORT_PASSKEY_STORAGE_KEY = 'passkeys';

  // State
  let parsedData: any = null;
  let newPasskeys: any[] = [];
  let existingIds: Set<string> = new Set();

  // DOM elements
  const dropZone = document.getElementById('drop-zone') as HTMLElement;
  const fileInput = document.getElementById('file-input') as HTMLInputElement;
  const chooseFileBtn = document.getElementById('choose-file-btn') as HTMLButtonElement;
  const statusEl = document.getElementById('status') as HTMLElement;
  const previewEl = document.getElementById('preview') as HTMLElement;
  const previewListEl = document.getElementById('preview-list') as HTMLElement;
  const actionsEl = document.getElementById('actions') as HTMLElement;
  const cancelBtn = document.getElementById('cancel-btn') as HTMLButtonElement;
  const importBtn = document.getElementById('import-btn') as HTMLButtonElement;
  const closeLink = document.getElementById('close-link') as HTMLAnchorElement;

  // Initialize
  setupEventListeners();

  function setupEventListeners(): void {
    // File input change
    fileInput.addEventListener('change', handleFileSelect);

    // Drag and drop
    dropZone.addEventListener('dragover', handleDragOver);
    dropZone.addEventListener('dragleave', handleDragLeave);
    dropZone.addEventListener('drop', handleDrop);

    // Buttons
    cancelBtn.addEventListener('click', resetState);
    importBtn.addEventListener('click', performImport);
    chooseFileBtn.addEventListener('click', () => fileInput.click());
    closeLink.addEventListener('click', (e) => {
      e.preventDefault();
      window.close();
    });
  }

  function handleDragOver(e: DragEvent): void {
    e.preventDefault();
    e.stopPropagation();
    dropZone.classList.add('drag-over');
  }

  function handleDragLeave(e: DragEvent): void {
    e.preventDefault();
    e.stopPropagation();
    dropZone.classList.remove('drag-over');
  }

  function handleDrop(e: DragEvent): void {
    e.preventDefault();
    e.stopPropagation();
    dropZone.classList.remove('drag-over');

    const files = e.dataTransfer?.files;
    if (files && files.length > 0) {
      processFile(files[0]);
    }
  }

  function handleFileSelect(e: Event): void {
    const input = e.target as HTMLInputElement;
    const file = input.files?.[0];
    if (file) {
      processFile(file);
    }
  }

  async function processFile(file: File): Promise<void> {
    // Reset state
    resetState();

    // Validate file type
    if (!file.name.endsWith('.json') && file.type !== 'application/json') {
      showStatus('Please select a JSON file', 'error');
      return;
    }

    try {
      const text = await file.text();
      parsedData = JSON.parse(text);

      // Validate structure
      if (!parsedData.passkeys || !Array.isArray(parsedData.passkeys)) {
        showStatus('Invalid file format: missing passkeys array', 'error');
        return;
      }

      // Check if this is a full backup (has private keys)
      const hasPrivateKeys = parsedData.passkeys.some((p: any) => p.privateKey);

      if (!hasPrivateKeys) {
        showStatus(
          'Cannot import: this file does not contain private keys. You need a full backup file.',
          'error'
        );
        return;
      }

      // Validate each passkey has required fields
      const validPasskeys = parsedData.passkeys.filter((p: any) => {
        return p.id && p.rpId && p.privateKey;
      });

      if (validPasskeys.length === 0) {
        showStatus('No valid passkeys found in file', 'error');
        return;
      }

      // Get existing passkeys to check for duplicates
      const result = await chrome.storage.local.get(IMPORT_PASSKEY_STORAGE_KEY);
      const existingPasskeys: any[] = result[IMPORT_PASSKEY_STORAGE_KEY] || [];
      existingIds = new Set(existingPasskeys.map((p) => p.id));

      // Separate new and duplicate passkeys
      newPasskeys = validPasskeys.filter((p: any) => !existingIds.has(p.id));
      const duplicates = validPasskeys.filter((p: any) => existingIds.has(p.id));

      // Show preview
      showPreview(validPasskeys, duplicates);

      if (newPasskeys.length === 0) {
        showStatus('All passkeys in this file already exist in your vault', 'info');
        return;
      }

      // Show info about what will be imported
      let message = `Found ${newPasskeys.length} new passkey${newPasskeys.length !== 1 ? 's' : ''} to import`;
      if (duplicates.length > 0) {
        message += ` (${duplicates.length} duplicate${duplicates.length !== 1 ? 's' : ''} will be skipped)`;
      }
      showStatus(message, 'info');

      // Show action buttons
      actionsEl.classList.remove('hidden');
    } catch (error) {
      console.error('Error processing file:', error);
      if (error instanceof SyntaxError) {
        showStatus('Invalid JSON file', 'error');
      } else {
        showStatus('Failed to process file: ' + (error as Error).message, 'error');
      }
    }
  }

  function showPreview(allPasskeys: any[], duplicates: any[]): void {
    previewListEl.innerHTML = '';

    allPasskeys.forEach((pk) => {
      const isDuplicate = duplicates.some((d) => d.id === pk.id);
      const item = document.createElement('div');
      item.className = 'preview-item';
      item.innerHTML = `
        <div>
          <div class="preview-item-site">${importEscapeHtml(pk.rpId || 'Unknown Site')}</div>
          <div class="preview-item-user">${importEscapeHtml(pk.user?.name || pk.user?.displayName || 'Unknown User')}</div>
        </div>
        <span class="preview-item-status ${isDuplicate ? 'duplicate' : 'new'}">
          ${isDuplicate ? 'Already exists' : 'New'}
        </span>
      `;
      previewListEl.appendChild(item);
    });

    previewEl.classList.add('visible');
  }

  async function performImport(): Promise<void> {
    if (newPasskeys.length === 0) {
      showStatus('No new passkeys to import', 'error');
      return;
    }

    try {
      // Get existing passkeys
      const result = await chrome.storage.local.get(IMPORT_PASSKEY_STORAGE_KEY);
      const existingPasskeys: any[] = result[IMPORT_PASSKEY_STORAGE_KEY] || [];

      // Merge
      const mergedPasskeys = [...existingPasskeys, ...newPasskeys];

      // Save
      await chrome.storage.local.set({ [IMPORT_PASSKEY_STORAGE_KEY]: mergedPasskeys });

      // Show success
      showStatus(
        `Successfully imported ${newPasskeys.length} passkey${newPasskeys.length !== 1 ? 's' : ''}!`,
        'success'
      );

      // Hide action buttons
      actionsEl.classList.add('hidden');

      // Update close link text
      closeLink.textContent = 'Close and return to extension';
    } catch (error) {
      console.error('Error importing passkeys:', error);
      showStatus('Failed to import passkeys: ' + (error as Error).message, 'error');
    }
  }

  function showStatus(message: string, type: 'success' | 'error' | 'info'): void {
    statusEl.textContent = message;
    statusEl.className = 'status ' + type;
  }

  function resetState(): void {
    parsedData = null;
    newPasskeys = [];
    existingIds = new Set();
    statusEl.className = 'status';
    statusEl.textContent = '';
    previewEl.classList.remove('visible');
    previewListEl.innerHTML = '';
    actionsEl.classList.add('hidden');
    fileInput.value = '';
  }

  function importEscapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text || '';
    return div.innerHTML;
  }
})();
