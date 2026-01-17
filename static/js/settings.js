document.addEventListener('DOMContentLoaded', () => {
    const toggleSwitch = document.getElementById('toggle-animations-switch');
    const isDisabled = localStorage.getItem('animationsDisabled') === 'true';

    // Set initial state based on storage
    // If animations DISABLED -> switch is CHECKED (or unchecked depending on logic)
    // Let's say: Checked = Animations Enabled (Default behavior usually)
    // OR: Checked = Disable Mode? 
    // User asked for "Enable/Disable" switch. 
    // Standard: Slider ON (Right) = Enabled. Slider OFF (Left) = Disabled.

    if (toggleSwitch) {
        // If disabled is true, then logic: enabled is false. 
        // So checked state should be !isDisabled
        toggleSwitch.checked = !isDisabled;

        toggleSwitch.addEventListener('change', (e) => {
            const isEnabled = e.target.checked;

            if (isEnabled) {
                // Enabled -> remove disable flag
                localStorage.removeItem('animationsDisabled');
            } else {
                // Disabled -> set flag
                localStorage.setItem('animationsDisabled', 'true');
            }

            // Reload to apply changes cleanly
            window.location.reload();
        });
    }
});
