const { useState, useEffect, useRef } = React;

const TerminalApp = () => {
    const [lines, setLines] = useState([]);
    const [currentCommand, setCurrentCommand] = useState('');
    const [cursorVisible, setCursorVisible] = useState(true);

    // Sequence states
    // 0: Initial prompt, typing 'nc -lvnp 1337'
    // 1: Running, showing 'listening on...'
    // 2: Connection received
    // 3: Shell prompt, typing 'whoami'
    // 4: Result 'root', final prompt
    const [stage, setStage] = useState(0);

    const textAreaRef = useRef(null);

    // Blinking cursor effect
    useEffect(() => {
        const interval = setInterval(() => {
            setCursorVisible(v => !v);
        }, 500);
        return () => clearInterval(interval);
    }, []);

    // Auto-scroll to bottom
    useEffect(() => {
        if (textAreaRef.current) {
            textAreaRef.current.scrollTop = textAreaRef.current.scrollHeight;
        }
    }, [lines, currentCommand]);

    // Typing Logic
    useEffect(() => {
        let timeout;

        const typeCommand = (cmd, callback) => {
            let i = 0;
            const typeChar = () => {
                if (i < cmd.length) {
                    setCurrentCommand(cmd.substring(0, i + 1));
                    i++;
                    timeout = setTimeout(typeChar, Math.random() * 100 + 50); // Random typing speed
                } else {
                    timeout = setTimeout(callback, 500);
                }
            };
            typeChar();
        };

        if (stage === 0) {
            // Wait a bit then type nc command
            timeout = setTimeout(() => {
                typeCommand('nc -lvnp 1337', () => {
                    setLines(prev => [...prev, { type: 'command', text: 'nc -lvnp 1337' }]);
                    setCurrentCommand('');
                    setStage(1);
                });
            }, 1000);
        } else if (stage === 1) {
            // Show listening output
            setLines(prev => [...prev,
            { type: 'output', text: 'listening on [any] 1337 ...' }
            ]);
            // Wait for "connection"
            timeout = setTimeout(() => {
                setStage(2);
            }, 2500);
        } else if (stage === 2) {
            // Connection received
            // Fake IP 10.10.14.8 (common HTB attacker IP) -> 10.129.x.x
            setLines(prev => [...prev,
            { type: 'output', text: 'connect to [10.10.14.8] from (UNKNOWN) [10.129.2.14] 4444' }
            ]);
            setStage(3);
        } else if (stage === 3) {
            // Type whoami
            timeout = setTimeout(() => {
                typeCommand('logname', () => {
                    setLines(prev => [...prev, { type: 'shell-command', text: 'logname' }]);
                    setCurrentCommand('');
                    setStage(4);
                });
            }, 1000);
        } else if (stage === 4) {
            // Show root and final prompt
            setLines(prev => [...prev, { type: 'output', text: 'jsmith' }]);
            setStage(5); // End state
        } else if (stage === 5) {
            // Type whoami
            timeout = setTimeout(() => {
                typeCommand('id', () => {
                    setLines(prev => [...prev, { type: 'shell-command', text: 'id' }]);
                    setCurrentCommand('');
                    setStage(6);
                });
            }, 1000);
        } else if (stage === 6) {
            // Show root and final prompt
            setLines(prev => [...prev, { type: 'output', text: 'uid=0(jsmith) gid=0(root) groups=0(root),27(sudo)' }]);
            setStage(7); // End state
        } else if (stage === 7) {
            // Type whoami
            timeout = setTimeout(() => {
                typeCommand('whoami', () => {
                    setLines(prev => [...prev, { type: 'shell-command', text: 'whoami' }]);
                    setCurrentCommand('');
                    setStage(8);
                });
            }, 1000);
        } else if (stage === 8) {
            // Show root and final prompt
            setLines(prev => [...prev, { type: 'output', text: 'root' }]);
            setStage(9); // End state
        } else if (stage === 9) {
            // Loop back to start after a delay? Or just stay? 
            // Let's loop for the "screensaver" feel
            timeout = setTimeout(() => {
                setLines([]);
                setStage(0);
            }, 5000);
        }

        return () => clearTimeout(timeout);
    }, [stage]);

    return (
        <div className="console-box glitch" ref={textAreaRef} style={{
            height: '100%',
            overflowY: 'hidden',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'flex-start',
            alignItems: 'flex-start',
            textAlign: 'left',
            fontFamily: "'Share Tech Mono', monospace"
        }}>
            <div className="console-header" style={{ width: '100%', marginBottom: '10px' }}>
                <div className="console-btn"></div>
                <div className="console-btn"></div>
                <div className="console-btn"></div>
            </div>

            {lines.map((line, idx) => (
                <div key={idx} className="console-line" style={{ width: '100%' }}>
                    {line.type === 'command' && <span style={{ color: '#00d9ff' }}>kali@kali:~$ {line.text}</span>}
                    {line.type === 'output' && <span style={{ color: '#0099bb' }}>{line.text}</span>}
                    {line.type === 'shell-command' && <span style={{ color: '#ff0055' }}># {line.text}</span>}
                </div>
            ))}

            <div className="console-line">
                {stage === 0 && <span style={{ color: '#00d9ff' }}>kali@kali:~$ {currentCommand}</span>}
                {stage === 1 && <span style={{ color: '#0099bb' }}>{/* Listening... */}</span>}
                {/* Stages 3, 5, 7, 8 are typing input */}
                {(stage === 3 || stage === 5 || stage === 7 || stage === 8) && <span style={{ color: '#ff0055' }}># {currentCommand}</span>}

                {/* Typing cursor during typing phases */}
                {(stage === 0 || stage === 3 || stage === 5 || stage === 7 || stage === 8) && (
                    <span className="cursor" style={{ opacity: cursorVisible ? 1 : 0, marginLeft: '2px' }}>_</span>
                )}
            </div>
        </div>
    );
};

const root = ReactDOM.createRoot(document.getElementById('react-terminal-root'));
root.render(<TerminalApp />);
