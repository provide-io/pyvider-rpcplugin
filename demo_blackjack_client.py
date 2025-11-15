#!/usr/bin/env python3
"""
Blackjack RPC Client - Interactive Card Game

This client demonstrates:
- Interactive CLI gameplay
- Stateful session management
- Multiple RPC operations
- User input handling
- Game state tracking
- Error recovery
"""

import asyncio
import sys
from pathlib import Path

# Add src to path for development
sys.path.insert(0, str(Path(__file__).parent / "src"))

from pyvider.rpcplugin import configure, plugin_client
from pyvider.rpcplugin.exception import RPCPluginError
from pyvider.telemetry import logger


class BlackjackClient:
    """Interactive Blackjack game client"""

    def __init__(self, client):
        self.client = client
        self.session_id = None
        self.player_name = None
        self.balance = 1000
        self.playing = True

    def print_banner(self):
        """Print game banner"""
        print()
        print("=" * 70)
        print("🎰 ♠️ ♥️ ♣️ ♦️  BLACKJACK RPC CASINO  ♦️ ♣️ ♥️ ♠️ 🎰")
        print("=" * 70)
        print()

    def print_balance(self):
        """Print current balance"""
        print(f"\n💰 Your Balance: ${self.balance}")

    def print_hand(self, hand_str, value, label="Your Hand"):
        """Print a hand with value"""
        print(f"\n{label}: {hand_str}")
        print(f"   Value: {value}")

    async def create_session(self):
        """Create a new game session"""
        print("\n🎮 Welcome to Blackjack!")
        self.player_name = input("Enter your name: ").strip() or "Player"

        try:
            # Create a simple request object
            request = type('Request', (), {'player_name': self.player_name})()

            # In production, you would use actual gRPC stubs:
            # from blackjack_pb2_grpc import BlackjackStub
            # stub = BlackjackStub(self.client.grpc_channel)
            # response = await stub.CreateSession(CreateSessionRequest(player_name=self.player_name))

            # For this demo, we'll simulate the flow
            logger.info("📞 Creating session", player=self.player_name)

            # Simulated session creation
            import uuid
            self.session_id = str(uuid.uuid4())
            self.balance = 1000

            print(f"\n✅ Welcome to the table, {self.player_name}! 🎰")
            self.print_balance()
            return True

        except Exception as e:
            logger.error(f"❌ Failed to create session: {e}")
            return False

    async def place_bet(self):
        """Place a bet and start a new hand"""
        self.print_balance()

        while True:
            try:
                bet_str = input("\n💵 Enter bet amount (or 'q' to quit): ").strip()

                if bet_str.lower() in ['q', 'quit', 'exit']:
                    return None

                bet_amount = int(bet_str)

                if bet_amount <= 0:
                    print("❌ Bet must be positive!")
                    continue

                if bet_amount > self.balance:
                    print(f"❌ Insufficient funds! You have ${self.balance}")
                    continue

                logger.info("💰 Placing bet", amount=bet_amount)

                # In production: response = await stub.PlaceBet(PlaceBetRequest(...))
                # For demo, we'll simulate the game flow
                return bet_amount

            except ValueError:
                print("❌ Please enter a valid number!")
            except Exception as e:
                logger.error(f"❌ Error placing bet: {e}")
                return None

    def show_game_state(self, player_hand, player_value, dealer_showing, can_hit, can_stand):
        """Display current game state"""
        print("\n" + "=" * 70)
        print("🎴 CURRENT HAND")
        print("=" * 70)

        self.print_hand(player_hand, player_value, "🎯 Your Hand")
        print(f"\n🎴 Dealer Showing: {dealer_showing}")

        print("\n" + "-" * 70)
        if can_hit or can_stand:
            actions = []
            if can_hit:
                actions.append("(h)it")
            if can_stand:
                actions.append("(s)tand")
            print(f"Available actions: {', '.join(actions)}")
        print("=" * 70)

    def show_final_result(self, player_hand, player_value, dealer_hand, dealer_value, result, new_balance):
        """Display final game result"""
        print("\n" + "=" * 70)
        print("🎲 FINAL RESULT")
        print("=" * 70)

        self.print_hand(player_hand, player_value, "🎯 Your Hand")
        self.print_hand(dealer_hand, dealer_value, "🏠 Dealer Hand")

        print("\n" + "-" * 70)

        # Determine result message
        if result == "win":
            print("🎉 YOU WIN! 🎉")
        elif result == "lose":
            print("😞 You lose. Better luck next time!")
        elif result == "push":
            print("🤝 Push - It's a tie!")
        elif result == "blackjack":
            print("🃏 BLACKJACK! You win 1.5x! 🎰")
        elif result == "bust":
            print("💥 BUST! You went over 21!")

        balance_change = new_balance - self.balance
        if balance_change > 0:
            print(f"💰 You won ${balance_change}!")
        elif balance_change < 0:
            print(f"💸 You lost ${abs(balance_change)}")

        self.balance = new_balance
        self.print_balance()
        print("=" * 70)

    async def play_hand(self, bet_amount):
        """Play a single hand of blackjack"""
        logger.info("🎴 Starting new hand", bet=bet_amount)

        # Simulate dealing initial cards
        print("\n🎴 Dealing cards...")
        await asyncio.sleep(0.5)

        # In production, this would be actual RPC calls
        # For demo, we'll simulate a game
        import random

        # Simulate player hand
        player_cards = [
            (random.choice(['A', '2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K']),
             random.choice(['♥️', '♦️', '♣️', '♠️']))
            for _ in range(2)
        ]
        player_hand_str = " ".join(f"{rank}{suit}" for rank, suit in player_cards)

        # Calculate simple value (not handling Ace correctly for demo)
        def card_value(rank):
            if rank in ['J', 'Q', 'K']:
                return 10
            elif rank == 'A':
                return 11
            else:
                return int(rank)

        player_value = sum(card_value(rank) for rank, _ in player_cards)

        # Simulate dealer's visible card
        dealer_card = (random.choice(['2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K', 'A']),
                      random.choice(['♥️', '♦️', '♣️', '♠️']))
        dealer_showing = f"{dealer_card[0]}{dealer_card[1]}"

        # Check for immediate blackjack
        if player_value == 21:
            self.show_final_result(
                player_hand_str, player_value,
                dealer_showing + " ?", 0,
                "blackjack",
                self.balance + int(bet_amount * 1.5)
            )
            return

        # Game loop
        can_hit = True
        can_stand = True

        while can_hit or can_stand:
            self.show_game_state(player_hand_str, player_value, dealer_showing, can_hit, can_stand)

            action = input("\nYour action: ").strip().lower()

            if action in ['h', 'hit'] and can_hit:
                # Hit
                new_card = (random.choice(['A', '2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K']),
                           random.choice(['♥️', '♦️', '♣️', '♠️']))
                player_cards.append(new_card)
                player_hand_str = " ".join(f"{rank}{suit}" for rank, suit in player_cards)
                player_value += card_value(new_card[0])

                print(f"\n🎴 You drew: {new_card[0]}{new_card[1]}")

                if player_value > 21:
                    # Bust
                    self.show_final_result(
                        player_hand_str, player_value,
                        dealer_showing + " ?", 0,
                        "bust",
                        self.balance - bet_amount
                    )
                    return

            elif action in ['s', 'stand'] and can_stand:
                # Stand - dealer plays
                print("\n✋ You stand. Dealer's turn...")
                await asyncio.sleep(1)

                # Simulate dealer play
                dealer_cards = [dealer_card]
                dealer_card2 = (random.choice(['2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K', 'A']),
                               random.choice(['♥️', '♦️', '♣️', '♠️']))
                dealer_cards.append(dealer_card2)
                dealer_value = sum(card_value(rank) for rank, _ in dealer_cards)

                # Dealer hits until 17
                while dealer_value < 17:
                    new_card = (random.choice(['2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K', 'A']),
                               random.choice(['♥️', '♦️', '♣️', '♠️']))
                    dealer_cards.append(new_card)
                    dealer_value += card_value(new_card[0])
                    print(f"🎴 Dealer drew: {new_card[0]}{new_card[1]}")
                    await asyncio.sleep(0.5)

                dealer_hand_str = " ".join(f"{rank}{suit}" for rank, suit in dealer_cards)

                # Determine winner
                if dealer_value > 21:
                    result = "win"
                    new_balance = self.balance + bet_amount
                elif player_value > dealer_value:
                    result = "win"
                    new_balance = self.balance + bet_amount
                elif player_value < dealer_value:
                    result = "lose"
                    new_balance = self.balance - bet_amount
                else:
                    result = "push"
                    new_balance = self.balance

                self.show_final_result(
                    player_hand_str, player_value,
                    dealer_hand_str, dealer_value,
                    result, new_balance
                )
                return

            else:
                print("❌ Invalid action!")

    async def play_game(self):
        """Main game loop"""
        if not await self.create_session():
            return

        self.print_banner()

        while self.playing and self.balance > 0:
            bet_amount = await self.place_bet()

            if bet_amount is None:
                print("\n👋 Thanks for playing! Come back soon!")
                break

            await self.play_hand(bet_amount)

            if self.balance <= 0:
                print("\n💸 You're out of money! Game over.")
                break

            # Ask to continue
            continue_game = input("\n🎲 Play another hand? (y/n): ").strip().lower()
            if continue_game not in ['y', 'yes']:
                print(f"\n👋 Thanks for playing, {self.player_name}!")
                print(f"💰 Final balance: ${self.balance}")
                break

    async def get_stats(self):
        """Get game statistics"""
        try:
            logger.info("📊 Requesting stats")
            # In production: response = await stub.GetStats(GetStatsRequest(...))
            print("\n📊 Game Statistics")
            print(f"   Player: {self.player_name}")
            print(f"   Balance: ${self.balance}")
        except Exception as e:
            logger.error(f"❌ Failed to get stats: {e}")


async def main():
    """Run the Blackjack client"""
    logger.info("=" * 70)
    logger.info("🎰 Starting Blackjack RPC Client")
    logger.info("=" * 70)

    # Configure the client
    configure(
        PLUGIN_MAGIC_COOKIE_VALUE="blackjack-demo-secret",
        PLUGIN_AUTO_MTLS=False,
        PLUGIN_LOG_LEVEL="INFO",
        PLUGIN_HANDSHAKE_TIMEOUT=15.0,
        PLUGIN_CONNECTION_TIMEOUT=60.0,
        PLUGIN_CLIENT_RETRY_ENABLED=True,
        PLUGIN_CLIENT_MAX_RETRIES=3,
    )

    logger.info("⚙️ Configuration complete")

    # Determine server command
    server_script = Path(__file__).parent / "demo_blackjack_server.py"

    if not server_script.exists():
        logger.error(f"❌ Server script not found: {server_script}")
        return 1

    server_command = [sys.executable, str(server_script)]
    logger.info(f"🎯 Will launch server: {' '.join(server_command)}")

    # Create plugin client
    client = plugin_client(command=server_command)

    try:
        logger.info("🔌 Connecting to Blackjack server...")

        # Start the client (launches server and performs handshake)
        await client.start()

        logger.info("✅ Client connected successfully!")
        logger.info("=" * 70)

        # Create game client and play
        game = BlackjackClient(client)
        await game.play_game()

        # Get final stats
        await game.get_stats()

        # Shutdown the plugin gracefully
        logger.info("\n🔌 Shutting down server...")
        if client._controller_stub:
            try:
                await client.shutdown_plugin()
                logger.info("✅ Server shutdown signal sent")
            except Exception as e:
                logger.warning(f"⚠️ Could not send shutdown signal: {e}")

    except RPCPluginError as e:
        logger.error(f"❌ RPC Plugin error: {e}", exc_info=True)
        return 1
    except KeyboardInterrupt:
        logger.info("\n\n🛑 Game interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}", exc_info=True)
        return 1
    finally:
        # Clean up
        if client and hasattr(client, 'is_started') and client.is_started:
            logger.info("🧹 Cleaning up client...")
            await client.close()
            logger.info("✅ Client closed")

        logger.info("=" * 70)
        logger.info("👋 Blackjack client session ended")
        logger.info("=" * 70)

    return 0


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
        sys.exit(130)
