import 'dart:math';
import 'package:flutter/material.dart';

// Placeholder for your LoginPage - ensure login_page.dart exists in your project
// import 'login_page.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'FindKal',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFF9ACAD0)),
        useMaterial3: true,
      ),
      home: const SplashScreen(),
    );
  }
}

class SplashScreen extends StatefulWidget {
  const SplashScreen({super.key});

  @override
  State<SplashScreen> createState() => _SplashScreenState();
}

class _SplashScreenState extends State<SplashScreen> with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late Animation<double> _logoOpacity;
  late Animation<double> _logoScale;
  late Animation<double> _circleScale;

  @override
  void initState() {
    super.initState();

    // Using a single controller for synchronized sequence
    _controller = AnimationController(
      duration: const Duration(milliseconds: 2500),
      vsync: this,
    );

    // 1. Logo fades in (0% to 30% of duration)
    // 2. Logo fades out as circle expands (60% to 85% of duration)
    _logoOpacity = TweenSequence<double>([
      TweenSequenceItem(
        tween: Tween<double>(begin: 0.0, end: 1.0).chain(CurveTween(curve: Curves.easeIn)),
        weight: 30,
      ),
      TweenSequenceItem(
        tween: ConstantTween<double>(1.0),
        weight: 30,
      ),
      TweenSequenceItem(
        tween: Tween<double>(begin: 1.0, end: 0.0).chain(CurveTween(curve: Curves.easeOut)),
        weight: 25,
      ),
      TweenSequenceItem(
        tween: ConstantTween<double>(0.0),
        weight: 15,
      ),
    ]).animate(_controller);

    // Logo subtle scale up during the first half
    _logoScale = Tween<double>(begin: 0.8, end: 1.1).animate(
      CurvedAnimation(
        parent: _controller,
        curve: const Interval(0.0, 0.6, curve: Curves.easeOut),
      ),
    );

    // Circle expansion starts after logo has been visible for a bit (50% to 90% of duration)
    _circleScale = Tween<double>(begin: 0.0, end: 3.0).animate(
      CurvedAnimation(
        parent: _controller,
        curve: const Interval(0.5, 0.9, curve: Curves.easeInOutCubic),
      ),
    );

    _controller.forward().then((_) => _navigateToLogin());
  }

  void _navigateToLogin() {
    if (!mounted) return;
    
    // Replace with your actual LoginPage navigation logic
    print("Animation complete. Navigating...");
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final size = MediaQuery.of(context).size;
    // Calculate size needed to cover the whole screen
    final maxDimension = max(size.width, size.height) * 1.5;

    return Scaffold(
      backgroundColor: Colors.white,
      body: Stack(
        alignment: Alignment.center,
        children: [
          // Expanding circle background
          AnimatedBuilder(
            animation: _circleScale,
            builder: (context, child) {
              return Transform.scale(
                scale: _circleScale.value,
                child: Container(
                  width: maxDimension,
                  height: maxDimension,
                  decoration: const BoxDecoration(
                    color: Color(0xFF9ACAD0),
                    shape: BoxShape.circle,
                  ),
                ),
              );
            },
          ),
          
          // Logo on top
          AnimatedBuilder(
            animation: _controller,
            builder: (context, child) {
              return Opacity(
                opacity: _logoOpacity.value,
                child: Transform.scale(
                  scale: _logoScale.value,
                  child: child,
                ),
              );
            },
            child: Image.asset(
              'assets/images/logo.png', 
              width: 150,
              errorBuilder: (context, error, stackTrace) => const Icon(
                Icons.location_on,
                size: 100,
                color: Color(0xFF9ACAD0),
              ),
            ),
          ),
        ],
      ),
    );
  }
}