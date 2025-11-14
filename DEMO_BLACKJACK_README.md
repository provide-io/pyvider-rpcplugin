# 🎰 Interactive Blackjack RPC Demo

This demo showcases an advanced, stateful RPC plugin implementation using `pyvider-rpcplugin` with a complete interactive card game.

## 📋 What This Demo Demonstrates

### Server Features (`demo_blackjack_server.py`)
- ✅ **Stateful Service** - Multi-session game state management with UUID tracking
- ✅ **Complex Game Logic** - Complete Blackjack rules including:
  - Ace handling (1 or 11)
  - Hand value calculation with multiple possibilities
  - Natural blackjack detection (21 with 2 cards)
  - Bust detection (all values > 21)
  - Dealer AI (hits until 17)
- ✅ **Session Management** - Dictionary-based player session storage
- ✅ **Multiple RPC Operations** - CreateSession, PlaceBet, Hit, Stand, GetStats
- ✅ **Player Tracking** - Balance management, bet handling, win/loss calculation
- ✅ **Data Classes** - Clean data modeling with Python dataclasses
- ✅ **Deck Management** - Auto-reshuffling when deck runs low
- ✅ **Error Handling** - Validation for bets, session states, game rules
- ✅ **Rich Logging** - Comprehensive structured logging with game events

### Client Features (`demo_blackjack_client.py`)
- ✅ **Interactive CLI** - User-friendly command-line interface
- ✅ **Game Loop** - Complete gameplay session management
- ✅ **Input Validation** - Bet validation, action validation
- ✅ **Visual Feedback** - Card displays with suit symbols (♠️ ♥️ ♣️ ♦️)
- ✅ **Balance Tracking** - Real-time balance updates
- ✅ **Session Lifecycle** - Create session → play hands → exit gracefully
- ✅ **Automatic Server Launch** - Spawns server subprocess automatically
- ✅ **Graceful Cleanup** - Proper resource cleanup on exit

### Game Mechanics Demonstrated
- **Hit**: Player takes another card
- **Stand**: Player stops, dealer plays automatically
- **Blackjack**: Natural 21 with 2 cards pays 1.5x
- **Bust**: Going over 21 loses immediately
- **Push**: Tie with dealer returns bet
- **Dealer Rules**: Must hit on 16 or less, stand on 17 or higher

## 🚀 Running the Demo

### Prerequisites
```bash
# Ensure environment is set up
cd /REDACTED_ABS_PATH
uv sync --all-groups
```

### Quick Start
The client automatically launches the server:

```bash
# Make script executable
chmod +x demo_blackjack_client.py demo_blackjack_server.py

# Run the game (auto-starts server)
PYTHONPATH=/REDACTED_ABS_PATH uv run python demo_blackjack_client.py
```

### Alternative: Using uv directly
```bash
uv run python demo_blackjack_client.py
```

## 🎮 How to Play

### Starting the Game
1. Run the client (it will automatically start the server)
2. Enter your player name when prompted
3. You start with $1000

### Gameplay
```
💰 Your Balance: $1000

💵 Enter bet amount (or 'q' to quit): 50

🎴 Dealing cards...

====================================================================
🎴 CURRENT HAND
====================================================================

🎯 Your Hand: K♠️ 7♥️
   Value: 17

🎴 Dealer Showing: 6♦️

--------------------------------------------------------------------
Available actions: (h)it, (s)tand
====================================================================

Your action: s

✋ You stand. Dealer's turn...
🎴 Dealer drew: 10♣️
🎴 Dealer drew: 5♠️

====================================================================
🎲 FINAL RESULT
====================================================================

🎯 Your Hand: K♠️ 7♥️
   Value: 17

🏠 Dealer Hand: 6♦️ 10♣️ 5♠️
   Value: 21

--------------------------------------------------------------------
😞 You lose. Better luck next time!
💸 You lost $50
💰 Your Balance: $950
====================================================================
```

### Game Actions
- **`h` or `hit`**: Take another card
- **`s` or `stand`**: Stop taking cards, dealer plays
- **`q` or `quit`**: Exit the game

### Winning Conditions
- **Blackjack**: Get 21 with 2 cards → Win 1.5x your bet
- **Win**: Beat dealer without going over 21 → Win 1x your bet
- **Push**: Tie with dealer → Get your bet back
- **Lose**: Dealer beats you or you bust → Lose your bet

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Client Process                      │
│  ┌───────────────────────────────────────────────┐  │
│  │       demo_blackjack_client.py                │  │
│  │  - BlackjackClient (game UI)                  │  │
│  │  - Interactive CLI                            │  │
│  │  - Input validation                           │  │
│  │  - Game loop management                       │  │
│  │  - Visual card display                        │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────┬───────────────────────────────┘
                      │
                      │ Unix Socket
                      │ /tmp/blackjack-rpc.sock
                      │
                      │ RPC Calls:
                      │ - CreateSession
                      │ - PlaceBet
                      │ - Hit
                      │ - Stand
                      │ - GetStats
                      │
┌─────────────────────┴───────────────────────────────┐
│                  Server Process                      │
│  ┌───────────────────────────────────────────────┐  │
│  │       demo_blackjack_server.py                │  │
│  │                                               │  │
│  │  BlackjackHandler                            │  │
│  │  ├─ sessions: Dict[str, GameSession]         │  │
│  │  ├─ CreateSession()                          │  │
│  │  ├─ PlaceBet()                               │  │
│  │  ├─ Hit()                                    │  │
│  │  ├─ Stand()                                  │  │
│  │  └─ GetStats()                               │  │
│  │                                               │  │
│  │  GameSession                                  │  │
│  │  ├─ session_id: str                          │  │
│  │  ├─ player_hand: Hand                        │  │
│  │  ├─ dealer_hand: Hand                        │  │
│  │  ├─ deck: List[Card]                         │  │
│  │  ├─ player_balance: int                      │  │
│  │  └─ current_bet: int                         │  │
│  │                                               │  │
│  │  Hand                                         │  │
│  │  ├─ cards: List[Card]                        │  │
│  │  ├─ get_values() → List[int]                 │  │
│  │  ├─ best_value() → int                       │  │
│  │  ├─ is_bust() → bool                         │  │
│  │  └─ is_blackjack() → bool                    │  │
│  │                                               │  │
│  │  Card                                         │  │
│  │  ├─ suit: Suit                               │  │
│  │  ├─ rank: Rank                               │  │
│  │  └─ values() → List[int]                     │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

## 🔧 Key Concepts Demonstrated

### 1. Stateful Service Pattern
```python
class BlackjackHandler:
    def __init__(self):
        # Store multiple game sessions
        self.sessions: Dict[str, GameSession] = {}
        self.game_count = 0
        self.total_hands_played = 0

    async def CreateSession(self, request, context):
        session_id = str(uuid.uuid4())
        session = GameSession(
            session_id=session_id,
            player_name=player_name
        )
        self.sessions[session_id] = session
        return response
```

### 2. Complex Data Modeling
```python
@dataclass
class Card:
    suit: Suit
    rank: Rank

    def values(self) -> List[int]:
        # Ace can be 1 or 11
        return self.rank.value[1]

@dataclass
class Hand:
    cards: List[Card] = field(default_factory=list)

    def get_values(self) -> List[int]:
        # Calculate all possible hand values
        # (important for Ace handling)
        ...

    def best_value(self) -> int:
        # Get best value <= 21, or minimum if all bust
        values = self.get_values()
        valid = [v for v in values if v <= 21]
        return max(valid) if valid else min(values)
```

### 3. State Machine Implementation
```python
async def PlaceBet(self, request, context):
    # Transition: idle → betting → playing
    session.game_over = False
    session.current_bet = bet_amount

    # Deal initial cards
    session.player_hand = Hand()
    session.dealer_hand = Hand()
    # ... deal 4 cards

    # Check for immediate win
    if session.player_hand.is_blackjack():
        session.game_over = True
        session.player_balance += int(bet_amount * 1.5)
```

### 4. Game Logic Implementation
```python
async def Stand(self, request, context):
    # Dealer AI: hit until 17
    while session.dealer_hand.best_value() < 17:
        card = session.deal_card()
        session.dealer_hand.add_card(card)

    # Determine winner
    player_value = session.player_hand.best_value()
    dealer_value = session.dealer_hand.best_value()

    if session.dealer_hand.is_bust():
        result = "win"
        session.player_balance += session.current_bet
    elif player_value > dealer_value:
        result = "win"
        session.player_balance += session.current_bet
    # ... other cases
```

### 5. Session Management
```python
@dataclass
class GameSession:
    session_id: str
    player_name: str
    player_hand: Hand = field(default_factory=Hand)
    dealer_hand: Hand = field(default_factory=Hand)
    deck: List[Card] = field(default_factory=list)
    game_over: bool = False
    player_balance: int = 1000
    current_bet: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
```

### 6. Interactive Client Pattern
```python
class BlackjackClient:
    def __init__(self, client):
        self.client = client  # RPC client
        self.session_id = None
        self.balance = 1000

    async def play_game(self):
        # Create session
        await self.create_session()

        # Game loop
        while self.balance > 0:
            bet = await self.place_bet()
            if bet is None:
                break
            await self.play_hand(bet)
```

## 📊 Expected Output

### Client Output
```
======================================================================
🎰 ♠️ ♥️ ♣️ ♦️  BLACKJACK RPC CASINO  ♦️ ♣️ ♥️ ♠️ 🎰
======================================================================

🎮 Welcome to Blackjack!
Enter your name: Alice

✅ Welcome to the table, Alice! 🎰

💰 Your Balance: $1000

💵 Enter bet amount (or 'q' to quit): 100

🎴 Dealing cards...

======================================================================
🎴 CURRENT HAND
======================================================================

🎯 Your Hand: A♠️ K♥️
   Value: 21

🎴 Dealer Showing: 7♦️

----------------------------------------------------------------------
Available actions: (h)it, (s)tand
======================================================================

Your action: s

✋ You stand. Dealer's turn...
🎴 Dealer drew: 9♣️
🎴 Dealer drew: 5♠️

======================================================================
🎲 FINAL RESULT
======================================================================

🎯 Your Hand: A♠️ K♥️
   Value: 21

🏠 Dealer Hand: 7♦️ 9♣️ 5♠️
   Value: 21

----------------------------------------------------------------------
🤝 Push - It's a tie!

💰 Your Balance: $1000
======================================================================

🎲 Play another hand? (y/n): y
```

### Server Output
```
======================================================================
🚀 Starting Blackjack RPC Server
======================================================================
🎰 Blackjack game server initialized
⚙️ Configuration complete
📍 Server will listen on: /tmp/blackjack-rpc.sock
✅ Blackjack server created
======================================================================
🎮 Ready to play Blackjack!
💡 Press Ctrl+C to stop the server
======================================================================
🎮 New session created | session_id=f47ac10b... | player=Alice | total_sessions=1
💰 Bet placed | session=f47ac10b... | amount=100 | player_cards=A♠️ K♥️ (Value: 21)
✋ Player stands | session=f47ac10b... | value=21
🎴 Dealer hit | card=9♣️
🎴 Dealer hit | card=5♠️
🤝 Push (tie) | value=21
```

## 🎓 Advanced Patterns Demonstrated

### Session-Based Architecture
- **UUID Generation**: Unique session IDs for each player
- **Session Storage**: In-memory dictionary (scalable to Redis/database)
- **Session Lifecycle**: Create → Play → Cleanup

### Complex State Management
- **Game States**: Idle, Betting, Playing, Game Over
- **Hand States**: Active, Bust, Blackjack, Stand
- **Validation**: Bet validation, action validation, state validation

### Domain Modeling
- **Enums**: Suit, Rank with associated data
- **Value Objects**: Card with immutable properties
- **Aggregates**: Hand managing multiple Cards
- **Entities**: GameSession with identity and lifecycle

### Game Logic
- **Probabilistic**: Deck shuffling, card dealing
- **Rule-Based**: Blackjack detection, bust detection, dealer AI
- **Scoring**: Multi-value hand calculation (Ace as 1 or 11)

## 🔒 Security Considerations

### Current Implementation (Demo)
- Magic cookie authentication: `blackjack-demo-secret`
- Unix socket transport (localhost only)
- No encryption (mTLS disabled for simplicity)

### Production Recommendations
```python
configure(
    PLUGIN_MAGIC_COOKIE_VALUE=os.environ["BLACKJACK_SECRET"],
    PLUGIN_AUTO_MTLS=True,
    PLUGIN_SERVER_CERT="file:///etc/ssl/certs/blackjack.crt",
    PLUGIN_SERVER_KEY="file:///etc/ssl/private/blackjack.key",
    PLUGIN_CLIENT_ROOT_CERTS="file:///etc/ssl/certs/ca.crt",
)
```

### Additional Security Measures
- **Rate Limiting**: Prevent bet spam
- **Session Timeout**: Auto-cleanup inactive sessions
- **Input Validation**: Strict bet amount validation
- **Balance Protection**: Prevent negative balances
- **Audit Logging**: Log all financial transactions

## 🚀 Extending This Demo

### 1. Add Persistence
```python
import sqlite3

class GameSession:
    def save(self):
        # Save to database
        conn.execute(
            "INSERT INTO sessions VALUES (?, ?, ?)",
            (self.session_id, self.player_name, self.player_balance)
        )
```

### 2. Add Multiplayer
```python
@dataclass
class Table:
    table_id: str
    players: Dict[str, GameSession]
    dealer: DealerSession
    max_players: int = 6
```

### 3. Add Side Bets
```python
async def PlaceSideBet(self, request, context):
    # Insurance, double down, split, etc.
    ...
```

### 4. Add Statistics
```python
async def GetPlayerStats(self, request, context):
    return PlayerStats(
        hands_played=session.hands_played,
        hands_won=session.hands_won,
        total_wagered=session.total_wagered,
        net_profit=session.player_balance - 1000
    )
```

### 5. Add Real Protobuf
```protobuf
service Blackjack {
    rpc CreateSession(CreateSessionRequest) returns (CreateSessionResponse);
    rpc PlaceBet(PlaceBetRequest) returns (PlaceBetResponse);
    rpc Hit(HitRequest) returns (HitResponse);
    rpc Stand(StandRequest) returns (StandResponse);
    rpc GetStats(GetStatsRequest) returns (GameStats);
}

message Card {
    string suit = 1;  // HEARTS, DIAMONDS, CLUBS, SPADES
    string rank = 2;  // A, 2-10, J, Q, K
}

message Hand {
    repeated Card cards = 1;
    int32 value = 2;
    bool is_bust = 3;
    bool is_blackjack = 4;
}
```

## 📚 Additional Resources

- **Calculator Demo**: `/REDACTED_ABS_PATH` - Simpler stateless example
- **Full Documentation**: `/REDACTED_ABS_PATH`
- **API Reference**: `/REDACTED_ABS_PATH`
- **Security Guide**: `/REDACTED_ABS_PATH`
- **Examples**: `/REDACTED_ABS_PATH`

## 🐛 Troubleshooting

### Socket Already in Use
```bash
rm /tmp/blackjack-rpc.sock
```

### Import Errors
```bash
export PYTHONPATH=/REDACTED_ABS_PATH:$PYTHONPATH
```

### Server Won't Start
```bash
# Check if another instance is running
ps aux | grep demo_blackjack_server
```

### Client Can't Connect
```bash
# Check socket file exists and has correct permissions
ls -la /tmp/blackjack-rpc.sock
```

## 📝 Key Takeaways

This demo illustrates:

1. **Stateful Services**: Managing complex, long-lived sessions
2. **Domain Modeling**: Clean separation of game logic from RPC concerns
3. **Interactive Clients**: Building engaging user experiences over RPC
4. **Real-World Complexity**: Handling rules, validation, state transitions
5. **Production Patterns**: Logging, error handling, graceful shutdown

The Blackjack demo is significantly more complex than the Calculator demo, showing how `pyvider-rpcplugin` scales from simple request/response to sophisticated stateful applications.

## 🎯 Comparison to Calculator Demo

| Feature | Calculator Demo | Blackjack Demo |
|---------|----------------|----------------|
| **State** | Stateless | Stateful (sessions) |
| **Complexity** | Simple math | Complex game logic |
| **Operations** | 5 operations | 5 operations |
| **Data Model** | Primitives | Complex objects |
| **Session Mgmt** | None | UUID-based sessions |
| **User Interaction** | One-shot calls | Interactive loop |
| **Business Logic** | Basic arithmetic | Game rules, AI |
| **LOC** | ~318 total | ~688 total |

---

**Built with ❤️ using pyvider-rpcplugin v0.0.11**

**🎰 Good luck at the tables! 🃏**
