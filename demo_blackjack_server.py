#!/usr/bin/env python3
"""
Blackjack RPC Server - Interactive Card Game Demo

This example demonstrates:
- Stateful service with session management
- Complex game logic and state machines
- Multi-operation RPC service
- Real-world application patterns
- Event-driven architecture
- Player session tracking
"""

import asyncio
import random
import signal
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, UTC
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

# Add src to path for development
sys.path.insert(0, str(Path(__file__).parent / "src"))

import grpc
from pyvider.rpcplugin import configure, plugin_server, plugin_protocol
from pyvider.telemetry import logger


class Suit(Enum):
    """Card suits"""
    HEARTS = "♥️"
    DIAMONDS = "♦️"
    CLUBS = "♣️"
    SPADES = "♠️"


class Rank(Enum):
    """Card ranks"""
    ACE = ("A", [1, 11])
    TWO = ("2", [2])
    THREE = ("3", [3])
    FOUR = ("4", [4])
    FIVE = ("5", [5])
    SIX = ("6", [6])
    SEVEN = ("7", [7])
    EIGHT = ("8", [8])
    NINE = ("9", [9])
    TEN = ("10", [10])
    JACK = ("J", [10])
    QUEEN = ("Q", [10])
    KING = ("K", [10])


@dataclass
class Card:
    """Playing card"""
    suit: Suit
    rank: Rank

    def __str__(self):
        return f"{self.rank.value[0]}{self.suit.value}"

    def values(self) -> List[int]:
        """Get possible values (Ace can be 1 or 11)"""
        return self.rank.value[1]


@dataclass
class Hand:
    """Player's hand"""
    cards: List[Card] = field(default_factory=list)

    def add_card(self, card: Card):
        """Add a card to the hand"""
        self.cards.append(card)

    def get_values(self) -> List[int]:
        """Calculate all possible hand values"""
        if not self.cards:
            return [0]

        # Start with first card's values
        possible_values = list(self.cards[0].values())

        # Add each subsequent card
        for card in self.cards[1:]:
            new_values = []
            for current_value in possible_values:
                for card_value in card.values():
                    new_values.append(current_value + card_value)
            possible_values = new_values

        return possible_values

    def best_value(self) -> int:
        """Get best value <= 21, or lowest value if all bust"""
        values = self.get_values()
        valid_values = [v for v in values if v <= 21]
        if valid_values:
            return max(valid_values)
        return min(values)

    def is_bust(self) -> bool:
        """Check if hand is bust (all values > 21)"""
        return all(v > 21 for v in self.get_values())

    def is_blackjack(self) -> bool:
        """Check if hand is a natural blackjack"""
        return len(self.cards) == 2 and self.best_value() == 21

    def __str__(self):
        cards_str = " ".join(str(card) for card in self.cards)
        return f"{cards_str} (Value: {self.best_value()})"


@dataclass
class GameSession:
    """A game session for a player"""
    session_id: str
    player_name: str
    player_hand: Hand = field(default_factory=Hand)
    dealer_hand: Hand = field(default_factory=Hand)
    deck: List[Card] = field(default_factory=list)
    game_over: bool = False
    player_balance: int = 1000
    current_bet: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self):
        """Initialize a fresh deck"""
        self.shuffle_deck()

    def shuffle_deck(self):
        """Create and shuffle a new deck"""
        self.deck = []
        for suit in Suit:
            for rank in Rank:
                self.deck.append(Card(suit, rank))
        random.shuffle(self.deck)
        logger.info("🃏 Deck shuffled", session=self.session_id, cards=len(self.deck))

    def deal_card(self) -> Card:
        """Deal a card from the deck"""
        if len(self.deck) < 10:
            logger.info("♻️ Deck running low, reshuffling", remaining=len(self.deck))
            self.shuffle_deck()
        return self.deck.pop()


class BlackjackHandler:
    """
    Blackjack game service handler.

    Manages multiple game sessions, implements game logic,
    and tracks player statistics.
    """

    def __init__(self):
        self.sessions: Dict[str, GameSession] = {}
        self.game_count = 0
        self.total_hands_played = 0
        logger.info("🎰 Blackjack game server initialized")

    async def CreateSession(self, request, context):
        """Create a new game session"""
        player_name = getattr(request, 'player_name', 'Player')
        session_id = str(uuid.uuid4())

        session = GameSession(
            session_id=session_id,
            player_name=player_name
        )

        self.sessions[session_id] = session
        self.game_count += 1

        logger.info(
            "🎮 New session created",
            session_id=session_id,
            player=player_name,
            total_sessions=len(self.sessions)
        )

        return type('Response', (), {
            'session_id': session_id,
            'player_name': player_name,
            'balance': session.player_balance,
            'message': f'Welcome to Blackjack, {player_name}! 🎰'
        })()

    async def PlaceBet(self, request, context):
        """Place a bet and start a new hand"""
        session_id = getattr(request, 'session_id', '')
        bet_amount = getattr(request, 'amount', 10)

        session = self.sessions.get(session_id)
        if not session:
            context.abort(grpc.StatusCode.NOT_FOUND, "Session not found")

        if bet_amount > session.player_balance:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Insufficient balance")

        if bet_amount <= 0:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Bet must be positive")

        # Start new hand
        session.player_hand = Hand()
        session.dealer_hand = Hand()
        session.current_bet = bet_amount
        session.game_over = False
        self.total_hands_played += 1

        # Deal initial cards
        session.player_hand.add_card(session.deal_card())
        session.dealer_hand.add_card(session.deal_card())
        session.player_hand.add_card(session.deal_card())
        session.dealer_hand.add_card(session.deal_card())

        logger.info(
            "💰 Bet placed",
            session=session_id,
            amount=bet_amount,
            player_cards=str(session.player_hand),
            dealer_showing=str(session.dealer_hand.cards[0])
        )

        # Check for natural blackjack
        result = ""
        if session.player_hand.is_blackjack():
            if session.dealer_hand.is_blackjack():
                result = "push"
                session.game_over = True
            else:
                result = "blackjack"
                session.player_balance += int(bet_amount * 1.5)
                session.game_over = True

        return type('Response', (), {
            'player_hand': str(session.player_hand),
            'dealer_showing': str(session.dealer_hand.cards[0]),
            'player_value': session.player_hand.best_value(),
            'can_hit': not session.game_over,
            'can_stand': not session.game_over,
            'result': result,
            'balance': session.player_balance
        })()

    async def Hit(self, request, context):
        """Player hits (takes another card)"""
        session_id = getattr(request, 'session_id', '')

        session = self.sessions.get(session_id)
        if not session:
            context.abort(grpc.StatusCode.NOT_FOUND, "Session not found")

        if session.game_over:
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, "Game is over")

        # Deal card to player
        card = session.deal_card()
        session.player_hand.add_card(card)

        logger.info(
            "🎴 Player hit",
            session=session_id,
            card=str(card),
            hand=str(session.player_hand)
        )

        # Check if bust
        result = ""
        if session.player_hand.is_bust():
            result = "bust"
            session.player_balance -= session.current_bet
            session.game_over = True
            logger.info("💥 Player bust!", session=session_id)

        return type('Response', (), {
            'player_hand': str(session.player_hand),
            'player_value': session.player_hand.best_value(),
            'dealer_showing': str(session.dealer_hand.cards[0]),
            'can_hit': not session.game_over,
            'can_stand': not session.game_over,
            'result': result,
            'balance': session.player_balance
        })()

    async def Stand(self, request, context):
        """Player stands (dealer plays)"""
        session_id = getattr(request, 'session_id', '')

        session = self.sessions.get(session_id)
        if not session:
            context.abort(grpc.StatusCode.NOT_FOUND, "Session not found")

        if session.game_over:
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, "Game is over")

        logger.info("✋ Player stands", session=session_id, value=session.player_hand.best_value())

        # Dealer plays (hits until 17 or higher)
        while session.dealer_hand.best_value() < 17:
            card = session.deal_card()
            session.dealer_hand.add_card(card)
            logger.info("🎴 Dealer hit", card=str(card))

        # Determine winner
        player_value = session.player_hand.best_value()
        dealer_value = session.dealer_hand.best_value()

        result = ""
        if session.dealer_hand.is_bust():
            result = "win"
            session.player_balance += session.current_bet
            logger.info("🎉 Player wins! Dealer bust", dealer_value=dealer_value)
        elif player_value > dealer_value:
            result = "win"
            session.player_balance += session.current_bet
            logger.info("🎉 Player wins!", player=player_value, dealer=dealer_value)
        elif player_value < dealer_value:
            result = "lose"
            session.player_balance -= session.current_bet
            logger.info("😞 Player loses", player=player_value, dealer=dealer_value)
        else:
            result = "push"
            logger.info("🤝 Push (tie)", value=player_value)

        session.game_over = True

        return type('Response', (), {
            'player_hand': str(session.player_hand),
            'dealer_hand': str(session.dealer_hand),
            'player_value': player_value,
            'dealer_value': dealer_value,
            'result': result,
            'balance': session.player_balance,
            'can_hit': False,
            'can_stand': False
        })()

    async def GetStats(self, request, context):
        """Get game statistics"""
        session_id = getattr(request, 'session_id', '')

        session = self.sessions.get(session_id)
        if not session:
            context.abort(grpc.StatusCode.NOT_FOUND, "Session not found")

        logger.info("📊 Stats requested", session=session_id)

        return type('Stats', (), {
            'player_name': session.player_name,
            'balance': session.player_balance,
            'hands_played': self.total_hands_played,
            'active_sessions': len(self.sessions),
            'session_age_seconds': int((datetime.now(UTC) - session.created_at).total_seconds())
        })()


async def main():
    """Run the Blackjack RPC server"""
    logger.info("=" * 70)
    logger.info("🎰 Starting Blackjack RPC Server")
    logger.info("=" * 70)

    # Configure the RPC plugin
    configure(
        PLUGIN_MAGIC_COOKIE_VALUE="blackjack-demo-secret",
        PLUGIN_AUTO_MTLS=False,
        PLUGIN_LOG_LEVEL="INFO",
        PLUGIN_HANDSHAKE_TIMEOUT=15.0,
        PLUGIN_CONNECTION_TIMEOUT=60.0,
        PLUGIN_RATE_LIMIT_ENABLED=True,
        PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=50.0,
        PLUGIN_RATE_LIMIT_BURST_CAPACITY=100,
        PLUGIN_HEALTH_SERVICE_ENABLED=True,
    )

    logger.info("⚙️ Configuration complete")

    # Create protocol and handler
    protocol = plugin_protocol()
    handler = BlackjackHandler()

    # Create server
    socket_path = "/tmp/blackjack-rpc.sock"
    logger.info(f"📍 Server will listen on: {socket_path}")

    server = plugin_server(
        protocol=protocol,
        handler=handler,
        transport="unix",
        transport_path=socket_path
    )

    logger.info("✅ Blackjack server created")
    logger.info("=" * 70)
    logger.info("🎮 Ready to play Blackjack!")
    logger.info("💡 Press Ctrl+C to stop the server")
    logger.info("=" * 70)

    # Set up signal handlers
    def signal_handler(signum, frame):
        logger.info(f"🛑 Received signal {signum}, shutting down...")
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    try:
        await server.serve()
    except KeyboardInterrupt:
        logger.info("🛑 Shutdown initiated")
    except Exception as e:
        logger.error("❌ Server error", error=str(e), exc_info=True)
    finally:
        logger.info("👋 Blackjack server stopped")
        logger.info("=" * 70)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("👋 Goodbye!")
