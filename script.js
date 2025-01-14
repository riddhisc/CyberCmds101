      
        const commandInput = document.getElementById('commandInput');
        const output = document.getElementById('output');
        const searchBar = document.getElementById('searchBar');
        const datetime = document.getElementById('datetime');
        const clearSearch = document.getElementById('clearSearch');
        const toggleHistory = document.getElementById('toggleHistory');
        const historyPanel = document.getElementById('historyPanel');
        let commandHistory = [];

        setInterval(() => {
            datetime.textContent = new Date().toLocaleString();
        }, 1000);

        const categories = {
            'network': {
                title: 'NETWORK SECURITY',
                commands: {
                    'nmap': 'Advanced port scanner and network mapper\nUsage: nmap [options] target\nKey options:\n-sS: Stealth scan\n-sV: Version detection\n-O: OS detection',
                    'wireshark': 'Network protocol analyzer\nUsage: GUI or tshark -i interface\nFeatures: Packet capture, protocol analysis, traffic inspection',
                    'tcpdump': 'Command-line packet analyzer\nUsage: tcpdump -i interface [options]',
                    'netstat': 'Network connection analyzer\nUsage: netstat -tuln',
                    'iptables': 'Firewall management\nUsage: iptables -A INPUT -p tcp --dport 80 -j ACCEPT'
                }
            },
            'web': {
                title: 'WEB SECURITY',
                commands: {
                    'burpsuite': 'Web application security testing\nFeatures: Proxy, Scanner, Intruder',
                    'sqlmap': 'SQL injection testing\nUsage: sqlmap -u URL --dbs',
                    'nikto': 'Web server scanner\nUsage: nikto -h target',
                    'dirb': 'Web content scanner\nUsage: dirb http://target',
                    'owasp-zap': 'Web app vulnerability scanner'
                }
            },
            'crypto': {
                title: 'CRYPTOGRAPHY',
                commands: {
                    'openssl': 'Cryptography toolkit\nUsage: openssl enc -aes-256-cbc -in file',
                    'hashcat': 'Password cracker\nUsage: hashcat -m 0 hash.txt wordlist.txt',
                    'gpg': 'File encryption\nUsage: gpg -c file',
                    'john': 'Password cracker\nUsage: john hash.txt',
                    'veracrypt': 'Disk encryption\nFeatures: Volume creation, mounting'
                }
            },
            'forensics': {
                title: 'FORENSICS',
                commands: {
                    'volatility': 'Memory analysis\nUsage: volatility -f mem.dump imageinfo',
                    'autopsy': 'Digital forensics suite\nFeatures: File analysis, timeline',
                    'dd': 'Disk imaging\nUsage: dd if=/dev/sda of=image.dd',
                    'exiftool': 'Metadata analyzer\nUsage: exiftool image.jpg',
                    'foremost': 'File carver\nUsage: foremost -t all -i disk.dd'
                }
            },
            'malware': {
                title: 'MALWARE ANALYSIS',
                commands: {
                    'ida': 'Interactive Disassembler\nFeatures: Code analysis, debugging',
                    'ghidra': 'Reverse engineering suite\nFeatures: Decompiler, analyzer',
                    'radare2': 'Reverse engineering framework\nUsage: r2 binary',
                    'cuckoo': 'Automated malware analysis\nUsage: cuckoo submit file',
                    'yara': 'Malware pattern matching\nUsage: yara rule.yar file'
                }
            }
        };

        function displayCategory(category) {
            if (!categories[category]) {
                return 'Category not found. Available categories: network, web, crypto, forensics, malware';
            }
            
            let output = `\n${categories[category].title}\n${'='.repeat(categories[category].title.length)}\n\n`;
            for (let cmd in categories[category].commands) {
                output += `${cmd}:\n${categories[category].commands[cmd]}\n\n`;
            }
            return output;
        }

        function handleCommand(cmd) {
            cmd = cmd.toLowerCase().trim();
            
            if (categories[cmd]) {
                return displayCategory(cmd);
            }

            if (cmd === 'help') {
                return `Available Categories:\n\n${Object.keys(categories).map(cat => 
                    `${categories[cat].title}\nType '${cat}' to view commands\n`).join('\n')}`;
            }

            for (let category in categories) {
                if (categories[category].commands[cmd]) {
                    return `${cmd}:\n${categories[category].commands[cmd]}`;
                }
            }

            return 'Command not found. Type "help" for available commands.';
        }

        function addToHistory(command) {
            commandHistory.unshift(command);
            if (commandHistory.length > 50) commandHistory.pop();
            updateHistoryPanel();
        }

        function updateHistoryPanel() {
            historyPanel.innerHTML = commandHistory
                .map(cmd => `<div class="history-entry">${cmd}</div>`)
                .join('');
            
            document.querySelectorAll('.history-entry').forEach(entry => {
                entry.addEventListener('click', () => {
                    commandInput.value = entry.textContent;
                    commandInput.focus();
                });
            });
        }

        function searchCommands(query) {
            query = query.toLowerCase();
            let results = '';
            
            for (let category in categories) {
                let categoryResults = '';
                let foundInCategory = false;
                
                for (let cmd in categories[category].commands) {
                    if (cmd.toLowerCase().includes(query) || 
                        categories[category].commands[cmd].toLowerCase().includes(query)) {
                        categoryResults += `\n${cmd}:\n${categories[category].commands[cmd]}\n`;
                        foundInCategory = true;
                    }
                }
                
                if (foundInCategory) {
                    results += `\n[${categories[category].title}]${categoryResults}\n`;
                }
            }
            
            return results || 'No results found. Try a different search term.';
        }

        // Improved search function
        function searchCommands(query) {
            query = query.toLowerCase().trim();
            if (!query) return 'Type a search term to begin...';
            if (query === 'help') return handleCommand('help');
            
            let results = '';
            let matchFound = false;
            
            for (let category in categories) {
                let categoryResults = '';
                
                for (let cmd in categories[category].commands) {
                    if (cmd.includes(query) || 
                        categories[category].commands[cmd].toLowerCase().includes(query)) {
                        categoryResults += `\n${cmd}:\n${categories[category].commands[cmd]}\n`;
                        matchFound = true;
                    }
                }
                
                if (categoryResults) {
                    results += `\n${categories[category].title}\n${'='.repeat(categories[category].title.length)}${categoryResults}\n`;
                }
            }
            
            return matchFound ? results : 'No matches found. Try "help" for available commands.';
        }

        // Training functionality
        const trainingSection = document.getElementById('trainingSection');
        const trainingContent = document.getElementById('trainingContent');
        const toggleTraining = document.getElementById('toggleTraining');
        const closeTraining = document.getElementById('closeTraining');
        const overlay = document.getElementById('overlay');

        async function fetchTrainingResources() {
            try {
                // Simulate API fetch
                const courses = [
                    { title: 'Network Security Fundamentals', difficulty: 'Beginner', duration: '4 weeks', link: '#' },
                    { title: 'Ethical Hacking Masterclass', difficulty: 'Advanced', duration: '8 weeks', link: '#' },
                    { title: 'Web Application Security', difficulty: 'Intermediate', duration: '6 weeks', link: '#' },
                    { title: 'Incident Response Training', difficulty: 'Intermediate', duration: '5 weeks', link: '#' }
                ];
                
                trainingContent.innerHTML = courses.map(course => `
                    <div class="command-block">
                        <h3>${course.title}</h3>
                        <p>Difficulty: ${course.difficulty}</p>
                        <p>Duration: ${course.duration}</p>
                        <a href="${course.link}" class="training-link">Start Training</a>
                    </div>
                `).join('');
            } catch (error) {
                trainingContent.innerHTML = 'Error loading training resources. Please try again.';
            }
        }

        // Event listeners
        toggleTraining.addEventListener('click', () => {
            trainingSection.style.display = 'block';
            overlay.style.display = 'block';
            fetchTrainingResources();
        });

        closeTraining.addEventListener('click', () => {
            trainingSection.style.display = 'none';
            overlay.style.display = 'none';
        });

        // Fix history panel behavior
        document.addEventListener('click', (e) => {
            if (!historyPanel.contains(e.target) && 
                !toggleHistory.contains(e.target)) {
                historyPanel.style.display = 'none';
            }
        });


        clearSearch.addEventListener('click', function() {
            searchBar.value = '';
            output.innerHTML = 'Search cleared. Type help for commands.\n';
        });

        toggleHistory.addEventListener('click', function() {
            historyPanel.style.display = historyPanel.style.display === 'none' ? 'block' : 'none';
        });

        commandInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                const input = this.value.trim();
                if (input) {
                    addToHistory(input);
                    output.innerHTML += `\n> ${input}\n`;
                    output.innerHTML += handleCommand(input);
                    this.value = '';
                    output.scrollTop = output.scrollHeight;
                }
            }
        });

        let searchTimeout;
        searchBar.addEventListener('input', function() {
            clearTimeout(searchTimeout);
            const query = this.value.trim();
            
            searchTimeout = setTimeout(() => {
                if (query.length >= 2) {
                    output.innerHTML = searchCommands(query);
                }
            }, 300);
        });

          // Update search event listener
          searchBar.addEventListener('input', function() {
            clearTimeout(searchTimeout);
            const query = this.value;
            
            searchTimeout = setTimeout(() => {
                output.innerHTML = searchCommands(query);
            }, 300);
        });

        historyPanel.style.display = 'none';
