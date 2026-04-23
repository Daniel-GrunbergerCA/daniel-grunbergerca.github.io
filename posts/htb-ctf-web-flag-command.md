# HTB Flag Command — Hidden Secret Command via JS Debug

Opening the challenge presents a game interface. We can run commands like `start`, `help`, `audio`, etc.

## Analysis

Analyzing the source code, every command we run (after starting the game) goes through `CheckMessage`:

```javascript
async function CheckMessage() {
    fetchingResponse = true;
    currentCommand = commandHistory[commandHistory.length - 1];

    if (availableOptions[currentStep].includes(currentCommand) || availableOptions['secret'].includes(currentCommand)) {
        await fetch('/api/monitor', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 'command': currentCommand })
        })
            .then((res) => res.json())
            .then(async (data) => {
                console.log(data)
                await displayLineInTerminal({ text: data.message });

                if(data.message.includes('Game over')) {
                    playerLost();
                    fetchingResponse = false;
                    return;
                }

                if(data.message.includes('HTB{')) {
                    playerWon();
                    fetchingResponse = false;
                    return;
                }
                // ...
            });
    }
}
```

The condition `availableOptions['secret'].includes(currentCommand)` stands out - there's a `secret` key alongside the normal step-based options. Opening DevTools and setting a breakpoint reveals its value.

## Exploit

Simply type that secret command into the game prompt and the API returns the flag:.

No exploitation needed - the server-side check accepts any command present in `availableOptions['secret']`, and the client exposes the entire object in plaintext JavaScript.
