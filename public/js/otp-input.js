class OTPInput {
    constructor(containerId, options = {}) {
        this.container = document.getElementById(containerId);
        this.length = options.length || 6;
        this.type = options.type || 'number';
        this.onComplete = options.onComplete || (() => {});
        this.inputs = [];
        
        this.init();
    }

    init() {
        // Create input fields
        for (let i = 0; i < this.length; i++) {
            const input = document.createElement('input');
            input.type = this.type;
            input.maxLength = 1;
            input.dataset.index = i;
            
            // Add event listeners
            input.addEventListener('input', (e) => this.handleInput(e));
            input.addEventListener('keydown', (e) => this.handleKeyDown(e));
            input.addEventListener('paste', (e) => this.handlePaste(e));
            
            this.inputs.push(input);
            this.container.appendChild(input);
        }

        // Add styles
        this.container.style.display = 'flex';
        this.container.style.gap = '8px';
        this.container.style.justifyContent = 'center';
        this.container.style.margin = '20px 0';

        this.inputs.forEach(input => {
            input.style.width = '40px';
            input.style.height = '40px';
            input.style.textAlign = 'center';
            input.style.fontSize = '20px';
            input.style.border = '1px solid #ccc';
            input.style.borderRadius = '4px';
            input.style.outline = 'none';
        });
    }

    handleInput(e) {
        const input = e.target;
        const index = parseInt(input.dataset.index);
        
        // Only allow numbers
        if (this.type === 'number' && !/^\d*$/.test(input.value)) {
            input.value = '';
            return;
        }

        // Move to next input if value is entered
        if (input.value.length === 1 && index < this.length - 1) {
            this.inputs[index + 1].focus();
        }

        // Check if all inputs are filled
        if (this.isComplete()) {
            this.onComplete(this.getValue());
        }
    }

    handleKeyDown(e) {
        const input = e.target;
        const index = parseInt(input.dataset.index);

        // Handle backspace
        if (e.key === 'Backspace') {
            if (input.value.length === 0 && index > 0) {
                this.inputs[index - 1].focus();
            }
        }
        // Handle arrow keys
        else if (e.key === 'ArrowLeft' && index > 0) {
            this.inputs[index - 1].focus();
        }
        else if (e.key === 'ArrowRight' && index < this.length - 1) {
            this.inputs[index + 1].focus();
        }
    }

    handlePaste(e) {
        e.preventDefault();
        const pastedData = e.clipboardData.getData('text').slice(0, this.length);
        
        // Only allow numbers if type is number
        if (this.type === 'number' && !/^\d*$/.test(pastedData)) {
            return;
        }

        // Fill inputs with pasted data
        for (let i = 0; i < pastedData.length; i++) {
            if (i < this.length) {
                this.inputs[i].value = pastedData[i];
            }
        }

        // Focus the next empty input or the last input
        const nextEmptyIndex = pastedData.length < this.length ? pastedData.length : this.length - 1;
        this.inputs[nextEmptyIndex].focus();

        // Check if all inputs are filled
        if (this.isComplete()) {
            this.onComplete(this.getValue());
        }
    }

    getValue() {
        return this.inputs.map(input => input.value).join('');
    }

    isComplete() {
        return this.inputs.every(input => input.value.length === 1);
    }

    clear() {
        this.inputs.forEach(input => {
            input.value = '';
        });
        this.inputs[0].focus();
    }

    focus() {
        this.inputs[0].focus();
    }
} 