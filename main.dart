import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'dart:convert';
import 'package:http/http.dart' as http;
import 'dart:async';

void main() {
  runApp(const URLScannerApp());
}

// ─── THEME COLORS ─────────────────────────────────────────────────────────────
const Color kBg = Color(0xFF0A0A0F);
const Color kSurface = Color(0xFF13131A);
const Color kCard = Color(0xFF1C1C26);
const Color kAccent = Color(0xFF6C63FF);
const Color kAccentGlow = Color(0x336C63FF);
const Color kSafe = Color(0xFF00E5A0);
const Color kDanger = Color(0xFFFF4560);
const Color kWarning = Color(0xFFFFB400);
const Color kText = Color(0xFFEEEEFF);
const Color kSubtext = Color(0xFF7B7B9D);

// ─── VIRUSTOTAL API KEY ────────────────────────────────────────────────────────
const String kApiKey = '53b872e25d1d4d95acacebfc37d4316b321efe4d06578fefe7fb2eb16bda7f8a'; // Replace with your VirusTotal API key

class URLScannerApp extends StatelessWidget {
  const URLScannerApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'URL Shield',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        brightness: Brightness.dark,
        scaffoldBackgroundColor: kBg,
        colorScheme: const ColorScheme.dark(
          primary: kAccent,
          surface: kSurface,
        ),
        textTheme: GoogleFonts.dmSansTextTheme(ThemeData.dark().textTheme),
      ),
      home: const ScannerScreen(),
    );
  }
}

// ─── SCANNER SCREEN ────────────────────────────────────────────────────────────
class ScannerScreen extends StatefulWidget {
  const ScannerScreen({super.key});

  @override
  State<ScannerScreen> createState() => _ScannerScreenState();
}

class _ScannerScreenState extends State<ScannerScreen>
    with TickerProviderStateMixin {
  final TextEditingController _urlController = TextEditingController();
  final FocusNode _focusNode = FocusNode();

  ScanState _state = ScanState.idle;
  ScanResult? _result;
  String _errorMsg = '';

  late AnimationController _pulseController;
  late AnimationController _radarController;

  @override
  void initState() {
    super.initState();
    _pulseController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    )..repeat(reverse: true);
    _radarController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    );
  }

  @override
  void dispose() {
    _pulseController.dispose();
    _radarController.dispose();
    _urlController.dispose();
    _focusNode.dispose();
    super.dispose();
  }

  Future<void> _scanUrl() async {
    final url = _urlController.text.trim();
    if (url.isEmpty) return;

    _focusNode.unfocus();
    setState(() {
      _state = ScanState.scanning;
      _result = null;
      _errorMsg = '';
    });
    _radarController.repeat();

    try {
      // Step 1: Submit URL
      final submitResp = await http.post(
        Uri.parse('https://www.virustotal.com/api/v3/urls'),
        headers: {
          'x-apikey': kApiKey,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: 'url=${Uri.encodeComponent(url)}',
      );

      if (submitResp.statusCode != 200) {
        throw Exception('Submission failed: ${submitResp.statusCode}');
      }

      final submitData = jsonDecode(submitResp.body);
      final analysisId = submitData['data']['id'];

      // Step 2: Poll for results
      ScanResult? result;
      for (int i = 0; i < 10; i++) {
        await Future.delayed(const Duration(seconds: 3));

        final analysisResp = await http.get(
          Uri.parse('https://www.virustotal.com/api/v3/analyses/$analysisId'),
          headers: {'x-apikey': kApiKey},
        );

        if (analysisResp.statusCode == 200) {
          final data = jsonDecode(analysisResp.body);
          final status = data['data']['attributes']['status'];

          if (status == 'completed') {
            final stats = data['data']['attributes']['stats'];
            final malicious = stats['malicious'] ?? 0;
            final suspicious = stats['suspicious'] ?? 0;
            final harmless = stats['harmless'] ?? 0;
            final undetected = stats['undetected'] ?? 0;
            final total = malicious + suspicious + harmless + undetected;

            result = ScanResult(
              url: url,
              malicious: malicious,
              suspicious: suspicious,
              harmless: harmless,
              undetected: undetected,
              total: total,
            );
            break;
          }
        }
      }

      _radarController.stop();
      _radarController.reset();

      if (result == null) {
        throw Exception('Scan timed out. Try again.');
      }

      setState(() {
        _state = ScanState.done;
        _result = result;
      });
    } catch (e) {
      _radarController.stop();
      _radarController.reset();
      setState(() {
        _state = ScanState.error;
        _errorMsg = e.toString().replaceAll('Exception: ', '');
      });
    }
  }

  void _reset() {
    setState(() {
      _state = ScanState.idle;
      _result = null;
      _errorMsg = '';
      _urlController.clear();
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: SingleChildScrollView(
          physics: const BouncingScrollPhysics(),
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 22, vertical: 20),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                _buildHeader(),
                const SizedBox(height: 36),
                _buildInputCard(),
                const SizedBox(height: 20),
                _buildScanButton(),
                const SizedBox(height: 32),
                if (_state == ScanState.scanning) _buildScanning(),
                if (_state == ScanState.done && _result != null)
                  _buildResult(_result!),
                if (_state == ScanState.error) _buildError(),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildHeader() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Container(
              width: 38,
              height: 38,
              decoration: BoxDecoration(
                color: kAccentGlow,
                borderRadius: BorderRadius.circular(10),
                border: Border.all(color: kAccent.withOpacity(0.5), width: 1),
              ),
              child: const Icon(Icons.shield_rounded,
                  color: kAccent, size: 20),
            ),
            const SizedBox(width: 12),
            Text(
              'URL Shield',
              style: GoogleFonts.spaceGrotesk(
                fontSize: 22,
                fontWeight: FontWeight.w700,
                color: kText,
                letterSpacing: -0.5,
              ),
            ),
            const Spacer(),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
              decoration: BoxDecoration(
                color: kSafe.withOpacity(0.1),
                borderRadius: BorderRadius.circular(20),
                border: Border.all(color: kSafe.withOpacity(0.3)),
              ),
              child: Text(
                'VirusTotal',
                style: GoogleFonts.dmMono(
                  fontSize: 10,
                  color: kSafe,
                  letterSpacing: 0.5,
                ),
              ),
            ),
          ],
        ),
        const SizedBox(height: 20),
        Text(
          'Scan any URL\nbefore you click.',
          style: GoogleFonts.spaceGrotesk(
            fontSize: 30,
            fontWeight: FontWeight.w800,
            color: kText,
            height: 1.2,
            letterSpacing: -1,
          ),
        ),
        const SizedBox(height: 8),
        Text(
          'Powered by 70+ security engines',
          style: GoogleFonts.dmSans(
            fontSize: 13,
            color: kSubtext,
          ),
        ),
      ],
    ).animate().fadeIn(duration: 500.ms).slideY(begin: -0.1, end: 0);
  }

  Widget _buildInputCard() {
    return Container(
      decoration: BoxDecoration(
        color: kCard,
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: kAccent.withOpacity(0.2), width: 1),
        boxShadow: [
          BoxShadow(
            color: kAccent.withOpacity(0.05),
            blurRadius: 20,
            spreadRadius: 2,
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(18, 16, 18, 0),
            child: Text(
              'ENTER URL',
              style: GoogleFonts.dmMono(
                fontSize: 10,
                color: kSubtext,
                letterSpacing: 2,
              ),
            ),
          ),
          TextField(
            controller: _urlController,
            focusNode: _focusNode,
            style: GoogleFonts.dmMono(
              color: kText,
              fontSize: 14,
            ),
            decoration: InputDecoration(
              hintText: 'https://example.com',
              hintStyle: GoogleFonts.dmMono(
                color: kSubtext.withOpacity(0.5),
                fontSize: 14,
              ),
              prefixIcon: const Icon(Icons.link_rounded,
                  color: kAccent, size: 18),
              suffixIcon: _urlController.text.isNotEmpty
                  ? IconButton(
                      icon: const Icon(Icons.clear_rounded,
                          color: kSubtext, size: 16),
                      onPressed: _reset,
                    )
                  : null,
              border: InputBorder.none,
              contentPadding: const EdgeInsets.symmetric(
                  horizontal: 18, vertical: 16),
            ),
            onChanged: (_) => setState(() {}),
            onSubmitted: (_) => _scanUrl(),
            keyboardType: TextInputType.url,
            autocorrect: false,
          ),
        ],
      ),
    ).animate().fadeIn(delay: 100.ms).slideY(begin: 0.05, end: 0);
  }

  Widget _buildScanButton() {
    final isLoading = _state == ScanState.scanning;
    return SizedBox(
      width: double.infinity,
      height: 54,
      child: ElevatedButton(
        onPressed: isLoading ? null : _scanUrl,
        style: ElevatedButton.styleFrom(
          backgroundColor: kAccent,
          disabledBackgroundColor: kAccent.withOpacity(0.4),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(14),
          ),
          elevation: 0,
        ),
        child: isLoading
            ? Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  SizedBox(
                    width: 16,
                    height: 16,
                    child: CircularProgressIndicator(
                      strokeWidth: 2,
                      color: kText.withOpacity(0.7),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Text(
                    'Scanning...',
                    style: GoogleFonts.spaceGrotesk(
                      fontSize: 15,
                      fontWeight: FontWeight.w600,
                      color: kText.withOpacity(0.7),
                    ),
                  ),
                ],
              )
            : Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  const Icon(Icons.radar_rounded, size: 18, color: Colors.white),
                  const SizedBox(width: 10),
                  Text(
                    'Scan URL',
                    style: GoogleFonts.spaceGrotesk(
                      fontSize: 15,
                      fontWeight: FontWeight.w700,
                      color: Colors.white,
                    ),
                  ),
                ],
              ),
      ),
    ).animate().fadeIn(delay: 200.ms);
  }

  Widget _buildScanning() {
    return Center(
      child: Column(
        children: [
          const SizedBox(height: 20),
          AnimatedBuilder(
            animation: _radarController,
            builder: (context, child) {
              return Stack(
                alignment: Alignment.center,
                children: [
                  ...List.generate(3, (i) {
                    final progress =
                        (_radarController.value + i / 3) % 1.0;
                    return Opacity(
                      opacity: (1 - progress).clamp(0.0, 1.0),
                      child: Container(
                        width: 60 + progress * 100,
                        height: 60 + progress * 100,
                        decoration: BoxDecoration(
                          shape: BoxShape.circle,
                          border: Border.all(
                            color: kAccent.withOpacity(0.6),
                            width: 1.5,
                          ),
                        ),
                      ),
                    );
                  }),
                  Container(
                    width: 60,
                    height: 60,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: kAccentGlow,
                      border: Border.all(color: kAccent, width: 2),
                    ),
                    child: const Icon(Icons.radar_rounded,
                        color: kAccent, size: 28),
                  ),
                ],
              );
            },
          ),
          const SizedBox(height: 20),
          Text(
            'Analyzing with 70+ engines...',
            style: GoogleFonts.dmSans(color: kSubtext, fontSize: 13),
          ),
          const SizedBox(height: 6),
          Text(
            'This may take 15–30 seconds',
            style: GoogleFonts.dmMono(
                color: kSubtext.withOpacity(0.5), fontSize: 11),
          ),
        ],
      ),
    ).animate().fadeIn();
  }

  Widget _buildResult(ScanResult result) {
    final isSafe = result.malicious == 0 && result.suspicious == 0;
    final isWarning = result.malicious == 0 && result.suspicious > 0;
    final isDanger = result.malicious > 0;

    final Color statusColor =
        isDanger ? kDanger : (isWarning ? kWarning : kSafe);
    final IconData statusIcon = isDanger
        ? Icons.dangerous_rounded
        : (isWarning ? Icons.warning_rounded : Icons.verified_rounded);
    final String statusText =
        isDanger ? 'MALICIOUS' : (isWarning ? 'SUSPICIOUS' : 'SAFE');

    return Column(
      children: [
        // Status Card
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(24),
          decoration: BoxDecoration(
            color: statusColor.withOpacity(0.08),
            borderRadius: BorderRadius.circular(20),
            border: Border.all(color: statusColor.withOpacity(0.3), width: 1.5),
          ),
          child: Column(
            children: [
              Icon(statusIcon, color: statusColor, size: 48),
              const SizedBox(height: 12),
              Text(
                statusText,
                style: GoogleFonts.spaceGrotesk(
                  fontSize: 24,
                  fontWeight: FontWeight.w800,
                  color: statusColor,
                  letterSpacing: 2,
                ),
              ),
              const SizedBox(height: 8),
              Text(
                isDanger
                    ? '${result.malicious} engine(s) flagged this URL as malicious.'
                    : isWarning
                        ? '${result.suspicious} engine(s) found this suspicious.'
                        : 'No threats detected. URL appears safe.',
                textAlign: TextAlign.center,
                style: GoogleFonts.dmSans(
                  fontSize: 13,
                  color: kSubtext,
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),

        // Stats Row
        Row(
          children: [
            _statBox('Malicious', result.malicious.toString(), kDanger),
            const SizedBox(width: 10),
            _statBox('Suspicious', result.suspicious.toString(), kWarning),
            const SizedBox(width: 10),
            _statBox('Clean', result.harmless.toString(), kSafe),
          ],
        ),
        const SizedBox(height: 16),

        // URL
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
            color: kCard,
            borderRadius: BorderRadius.circular(12),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text('SCANNED URL',
                  style: GoogleFonts.dmMono(
                      fontSize: 9, color: kSubtext, letterSpacing: 2)),
              const SizedBox(height: 6),
              Text(
                result.url,
                style: GoogleFonts.dmMono(
                    fontSize: 12, color: kText.withOpacity(0.8)),
                overflow: TextOverflow.ellipsis,
                maxLines: 2,
              ),
            ],
          ),
        ),
        const SizedBox(height: 20),

        // Scan Again
        SizedBox(
          width: double.infinity,
          height: 48,
          child: OutlinedButton(
            onPressed: _reset,
            style: OutlinedButton.styleFrom(
              side: BorderSide(color: kAccent.withOpacity(0.4)),
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(12)),
            ),
            child: Text(
              'Scan Another URL',
              style: GoogleFonts.spaceGrotesk(
                  fontSize: 14,
                  fontWeight: FontWeight.w600,
                  color: kAccent),
            ),
          ),
        ),
      ],
    ).animate().fadeIn().slideY(begin: 0.1, end: 0);
  }

  Widget _statBox(String label, String value, Color color) {
    return Expanded(
      child: Container(
        padding: const EdgeInsets.symmetric(vertical: 14),
        decoration: BoxDecoration(
          color: color.withOpacity(0.08),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: color.withOpacity(0.2)),
        ),
        child: Column(
          children: [
            Text(
              value,
              style: GoogleFonts.spaceGrotesk(
                fontSize: 22,
                fontWeight: FontWeight.w800,
                color: color,
              ),
            ),
            Text(
              label,
              style: GoogleFonts.dmSans(fontSize: 11, color: kSubtext),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildError() {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: kDanger.withOpacity(0.08),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: kDanger.withOpacity(0.3)),
      ),
      child: Column(
        children: [
          const Icon(Icons.error_outline_rounded, color: kDanger, size: 32),
          const SizedBox(height: 10),
          Text('Scan Failed',
              style: GoogleFonts.spaceGrotesk(
                  fontSize: 16,
                  fontWeight: FontWeight.w700,
                  color: kDanger)),
          const SizedBox(height: 6),
          Text(_errorMsg,
              textAlign: TextAlign.center,
              style: GoogleFonts.dmSans(fontSize: 12, color: kSubtext)),
          const SizedBox(height: 14),
          TextButton(
            onPressed: _reset,
            child: Text('Try Again',
                style: GoogleFonts.dmSans(color: kAccent, fontSize: 13)),
          ),
        ],
      ),
    ).animate().fadeIn().shakeX();
  }
}

// ─── MODELS ───────────────────────────────────────────────────────────────────
enum ScanState { idle, scanning, done, error }

class ScanResult {
  final String url;
  final int malicious;
  final int suspicious;
  final int harmless;
  final int undetected;
  final int total;

  ScanResult({
    required this.url,
    required this.malicious,
    required this.suspicious,
    required this.harmless,
    required this.undetected,
    required this.total,
  });
}
