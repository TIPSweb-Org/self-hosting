class SessionManager {
    constructor(userEmail) {
      this.userEmail = userEmail;
      this.bindElements();
      this.bindEvents();
      this.checkExistingSession();
    }
  
    bindElements() {
      this.launchBtn = document.getElementById('launchBtn');
      this.getBtn = document.getElementById('getSessionBtn');
      this.delBtn = document.getElementById('deleteSessionBtn');
      this.output = document.getElementById('sessionOutput');
    }
  
    bindEvents() {
      this.launchBtn.addEventListener('click', () => this.startSession());
      this.getBtn.addEventListener('click', () => this.openSession());
      this.delBtn.addEventListener('click', () => this.deleteSession());
    }
  
    toggleButtons(sessionActive) {
      this.launchBtn.style.display = sessionActive ? 'none' : 'inline-block';
      this.getBtn.style.display = sessionActive ? 'inline-block' : 'none';
      this.delBtn.style.display = sessionActive ? 'inline-block' : 'none';
    }
  
    async checkExistingSession() {
      try {
        const response = await this.apiRequest('/get_session', 'POST');
        if (response && response.stream_id) {
          this.toggleButtons(true);
          this.output.textContent = 'Session exists. Click "Open Session" to connect.';
        }
      } catch (error) {
        console.error('Session check failed:', error);
      }
    }
  
    async startSession() {
      try {
        const response = await this.apiRequest('/start_session', 'POST');
        if (response.stream_id) {
          this.output.textContent = "Session started successfully!\n\n" +
            "It may take a second to start TIPS\n" +
            "just reload the page if it fails.";
          this.toggleButtons(true);
        }
      } catch (error) {
        this.output.textContent = `Failed to start session: ${error.message}`;
      }
    }
  
    async openSession() {
      try {
        const response = await this.apiRequest('/get_session', 'POST');
        if (response.stream_id) {
          // Use the stream endpoint instead of direct IP
          const streamUrl = `/stream/${response.stream_id}`;
          window.open(streamUrl, '_blank');
        } else {
          this.output.textContent = 'No active session found.';
        }
      } catch (error) {
        this.output.textContent = `Error: ${error.message}`;
      }
    }
  
    async deleteSession() {
      try {
        const response = await this.apiRequest('/delete_session', 'DELETE');
        if (response.status === 'Session deleted') {
          this.output.textContent = 'Session ended successfully.';
          this.toggleButtons(false);
        }
      } catch (error) {
        this.output.textContent = `Error: ${error.message}`;
      }
    }
  
    async apiRequest(endpoint, method) {
      const response = await fetch(endpoint, {
        method,
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user: this.userEmail })
      });
  
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Request failed');
      }
  
      return await response.json();
    }
  }
  
  // Initialize when loaded
  function initSessionManager(userEmail) {
    new SessionManager(userEmail);
  }