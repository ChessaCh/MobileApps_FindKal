import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'services/api_service.dart';

const String _apiBase = 'https://api-regional-indonesia.vercel.app/api';

class RegisterAddressPage extends StatefulWidget {
  final String name;
  final String username;
  final String password;
  final String email;

  const RegisterAddressPage({
    super.key,
    required this.name,
    required this.username,
    required this.password,
    required this.email,
  });

  @override
  State<RegisterAddressPage> createState() => _RegisterAddressPageState();
}

class _RegisterAddressPageState extends State<RegisterAddressPage> {
  // Selected IDs — used to fetch the next level
  String? _selectedProvinceId;
  String? _selectedCityId;
  String? _selectedDistrictId;

  // Selected names — displayed and eventually sent to backend
  String? _selectedProvince;
  String? _selectedCity;
  String? _selectedDistrict;
  String? _selectedVillage;

  // Loaded lists for each level
  List<Map<String, String>> _provinces = [];
  List<Map<String, String>> _cities = [];
  List<Map<String, String>> _districts = [];
  List<Map<String, String>> _villages = [];

  // Loading flags
  bool _loadingProvinces = false;
  bool _loadingCities = false;
  bool _loadingDistricts = false;
  bool _loadingVillages = false;
  bool _submitting = false;

  @override
  void initState() {
    super.initState();
    _loadProvinces();
  }

  Future<List<Map<String, String>>> _fetch(String url) async {
    final response = await http.get(Uri.parse(url));
    if (response.statusCode != 200) {
      throw Exception('Gagal memuat data (${response.statusCode})');
    }
    final body = jsonDecode(response.body) as Map<String, dynamic>;
    final data = body['data'] as List<dynamic>;
    return data
        .map((e) => {
              'id': e['id'].toString(),
              'name': e['name'].toString(),
            })
        .toList();
  }

  Future<void> _loadProvinces() async {
    setState(() => _loadingProvinces = true);
    try {
      final list = await _fetch('$_apiBase/provinces');
      setState(() => _provinces = list);
    } catch (_) {
      // silently fail — user can retry by re-entering the page
    } finally {
      setState(() => _loadingProvinces = false);
    }
  }

  Future<void> _onProvinceChanged(String id, String name) async {
    setState(() {
      _selectedProvinceId = id;
      _selectedProvince = name;
      _selectedCityId = null;
      _selectedCity = null;
      _selectedDistrictId = null;
      _selectedDistrict = null;
      _selectedVillage = null;
      _cities = [];
      _districts = [];
      _villages = [];
      _loadingCities = true;
    });
    try {
      final list = await _fetch('$_apiBase/cities/$id');
      setState(() => _cities = list);
    } catch (_) {
    } finally {
      setState(() => _loadingCities = false);
    }
  }

  Future<void> _onCityChanged(String id, String name) async {
    setState(() {
      _selectedCityId = id;
      _selectedCity = name;
      _selectedDistrictId = null;
      _selectedDistrict = null;
      _selectedVillage = null;
      _districts = [];
      _villages = [];
      _loadingDistricts = true;
    });
    try {
      final list = await _fetch('$_apiBase/districts/$id');
      setState(() => _districts = list);
    } catch (_) {
    } finally {
      setState(() => _loadingDistricts = false);
    }
  }

  Future<void> _onDistrictChanged(String id, String name) async {
    setState(() {
      _selectedDistrictId = id;
      _selectedDistrict = name;
      _selectedVillage = null;
      _villages = [];
      _loadingVillages = true;
    });
    try {
      final list = await _fetch('$_apiBase/villages/$id');
      setState(() => _villages = list);
    } catch (_) {
    } finally {
      setState(() => _loadingVillages = false);
    }
  }

  bool get _allSelected =>
      _selectedProvince != null &&
      _selectedCity != null &&
      _selectedDistrict != null &&
      _selectedVillage != null;

  Future<void> _onBuatAkun() async {
    setState(() => _submitting = true);
    try {
      await ApiService.register(
        name: widget.name,
        username: widget.username,
        password: widget.password,
        email: widget.email,
        negara: 'Indonesia',
        provinsi: _selectedProvince!,
        kota: _selectedCity!,
        kecamatan: _selectedDistrict!,
        kelurahan: _selectedVillage!,
      );
      if (!mounted) return;
      Navigator.pushNamedAndRemoveUntil(context, '/login', (_) => false);
    } on ApiException catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(e.message,
              style: const TextStyle(fontFamily: 'Inter')),
          backgroundColor: Colors.redAccent,
          behavior: SnackBarBehavior.floating,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
          margin: const EdgeInsets.only(bottom: 20, left: 24, right: 24),
        ),
      );
    } finally {
      if (mounted) setState(() => _submitting = false);
    }
  }

  // ── Widgets ──────────────────────────────────────────────────────────────

  Widget _buildReadOnly(String label, String value) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: const TextStyle(
            fontFamily: 'Inter',
            fontSize: 14,
            fontWeight: FontWeight.w500,
            color: Colors.black,
          ),
        ),
        const SizedBox(height: 6),
        Container(
          height: 40,
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(30),
            border: Border.all(color: Colors.grey.shade300),
            color: Colors.grey.shade100,
          ),
          padding: const EdgeInsets.symmetric(horizontal: 16),
          alignment: Alignment.centerLeft,
          child: Text(
            value,
            style: TextStyle(
              fontFamily: 'Inter',
              fontSize: 14,
              color: Colors.grey.shade600,
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildDropdown({
    required String label,
    required List<Map<String, String>> items,
    required String? value,
    required void Function(String id, String name)? onChanged,
    bool loading = false,
  }) {
    final bool enabled = !loading && items.isNotEmpty;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: const TextStyle(
            fontFamily: 'Inter',
            fontSize: 14,
            fontWeight: FontWeight.w500,
            color: Colors.black,
          ),
        ),
        const SizedBox(height: 6),
        Container(
          height: 40,
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(30),
            border: Border.all(
              color: enabled ? Colors.grey.shade400 : Colors.grey.shade300,
            ),
            color: enabled ? Colors.white : Colors.grey.shade100,
          ),
          padding: const EdgeInsets.symmetric(horizontal: 16),
          child: loading
              ? const Center(
                  child: SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(
                      strokeWidth: 2,
                      color: Color(0xFF4AA5A6),
                    ),
                  ),
                )
              : DropdownButtonHideUnderline(
                  child: DropdownButton<String>(
                    isExpanded: true,
                    value: value,
                    hint: Text(
                      enabled ? 'Pilih $label' : '',
                      style: TextStyle(
                        fontFamily: 'Inter',
                        fontSize: 14,
                        color: Colors.grey.shade400,
                      ),
                    ),
                    icon: Icon(
                      Icons.unfold_more,
                      size: 20,
                      color: enabled
                          ? Colors.grey.shade700
                          : Colors.grey.shade400,
                    ),
                    style: const TextStyle(
                      fontFamily: 'Inter',
                      fontSize: 14,
                      color: Colors.black,
                    ),
                    onChanged: enabled
                        ? (selectedName) {
                            if (selectedName == null) return;
                            final item = items.firstWhere(
                              (e) => e['name'] == selectedName,
                            );
                            onChanged!(item['id']!, item['name']!);
                          }
                        : null,
                    items: items
                        .map(
                          (e) => DropdownMenuItem<String>(
                            value: e['name'],
                            child: Text(
                              e['name']!,
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                        )
                        .toList(),
                  ),
                ),
        ),
      ],
    );
  }

  // ── Build ─────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.white,
      appBar: AppBar(
        backgroundColor: Colors.white,
        elevation: 0,
        toolbarHeight: 80,
        leading: Padding(
          padding: const EdgeInsets.only(top: 30.0),
          child: IconButton(
            icon: const Icon(
              Icons.arrow_back_ios_new,
              color: Color(0xFF4AA5A6),
              size: 20,
            ),
            onPressed: () => Navigator.pop(context),
          ),
        ),
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 24.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const SizedBox(height: 40),
              const Text(
                "Sign up",
                style: TextStyle(
                  fontFamily: 'Inter',
                  fontSize: 32,
                  fontWeight: FontWeight.bold,
                  color: Colors.black,
                ),
              ),
              const SizedBox(height: 25),

              // Negara — locked to Indonesia
              _buildReadOnly("Negara", "Indonesia"),
              const SizedBox(height: 16),

              // Provinsi
              _buildDropdown(
                label: "Provinsi",
                items: _provinces,
                value: _selectedProvince,
                loading: _loadingProvinces,
                onChanged: (id, name) => _onProvinceChanged(id, name),
              ),
              const SizedBox(height: 16),

              // Kota
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Expanded(
                    child: _buildDropdown(
                      label: "Kota",
                      items: _cities,
                      value: _selectedCity,
                      loading: _loadingCities,
                      onChanged: _selectedProvinceId != null
                          ? (id, name) => _onCityChanged(id, name)
                          : null,
                    ),
                  ),
                  const SizedBox(width: 16),
                  // Kecamatan
                  Expanded(
                    child: _buildDropdown(
                      label: "Kecamatan",
                      items: _districts,
                      value: _selectedDistrict,
                      loading: _loadingDistricts,
                      onChanged: _selectedCityId != null
                          ? (id, name) => _onDistrictChanged(id, name)
                          : null,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 16),

              // Kelurahan — full width
              _buildDropdown(
                label: "Kelurahan",
                items: _villages,
                value: _selectedVillage,
                loading: _loadingVillages,
                onChanged: _selectedDistrictId != null
                    ? (_, name) =>
                        setState(() => _selectedVillage = name)
                    : null,
              ),

              const Spacer(),

              // Buat akun button
              SizedBox(
                width: double.infinity,
                height: 48,
                child: ElevatedButton(
                  onPressed: _allSelected && !_submitting ? _onBuatAkun : null,
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFFA5D1D6),
                    disabledBackgroundColor: Colors.grey.shade300,
                    foregroundColor: Colors.white,
                    disabledForegroundColor: Colors.grey.shade500,
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(30),
                    ),
                    elevation: 0,
                  ),
                  child: _submitting
                      ? const SizedBox(
                          width: 20,
                          height: 20,
                          child: CircularProgressIndicator(
                              strokeWidth: 2, color: Colors.white),
                        )
                      : const Text(
                          "Buat akun",
                          style: TextStyle(
                            fontFamily: 'Inter',
                            fontSize: 16,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                ),
              ),
              const SizedBox(height: 40),
            ],
          ),
        ),
      ),
    );
  }
}
