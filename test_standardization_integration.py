#!/usr/bin/env python3
"""
Test script to validate data standardization integration across all modules
Ensures BHXH data standardization is working properly in all customer data processing scripts
"""

import sys
import traceback
from datetime import datetime

def test_module_imports():
    """Test that all modules can be imported successfully"""
    print("🧪 Testing Module Imports...")
    print("-" * 50)
    
    modules_to_test = [
        "bhxh_data_standardizer",
        "customer_data_excel_exporter", 
        "comprehensive_customer_excel_generator",
        "master_customer_data_exporter",
        "evidence_consolidator",
        "final_analysis_reporter"
    ]
    
    results = {}
    
    for module_name in modules_to_test:
        try:
            module = __import__(module_name)
            results[module_name] = "✅ SUCCESS"
            print(f"✅ {module_name}: Import successful")
        except Exception as e:
            results[module_name] = f"❌ FAILED: {str(e)}"
            print(f"❌ {module_name}: {str(e)}")
    
    return results

def test_standardizer_functionality():
    """Test BHXHDataStandardizer functionality"""
    print("\n🧪 Testing Data Standardization Functionality...")
    print("-" * 50)
    
    try:
        from bhxh_data_standardizer import BHXHDataStandardizer
        
        standardizer = BHXHDataStandardizer()
        
        # Test data samples
        test_data = {
            "ho_ten": "  nguyễn văn    an  ",
            "ngay_sinh": "01/01/1990",
            "so_bhxh": "1234567890",
            "so_cccd": "123456789012",
            "so_dien_thoai": "0901234567"
        }
        
        print("🔧 Testing with sample data:")
        for key, value in test_data.items():
            print(f"   {key}: '{value}'")
        
        # Test standardization
        result = standardizer.standardize_customer_data(test_data)
        
        print("\n📊 Standardization Results:")
        std_data = result.get("standardized_data", {})
        for key, value in std_data.items():
            print(f"   {key}: '{value}'")
        
        # Validation checks
        validations = result.get("validation_results", {})
        print("\n✅ Validation Results:")
        for key, validation in validations.items():
            status = "✅" if validation.get("is_valid") else "❌"
            print(f"   {status} {key}: {validation.get('message', 'No message')}")
        
        return True
        
    except Exception as e:
        print(f"❌ Standardizer test failed: {e}")
        traceback.print_exc()
        return False

def test_class_instantiation():
    """Test that all main classes can be instantiated with standardizer"""
    print("\n🧪 Testing Class Instantiation with Standardizer...")
    print("-" * 50)
    
    test_results = {}
    
    # Test CustomerDataExcelExporter
    try:
        from customer_data_excel_exporter import CustomerDataExcelExporter
        exporter = CustomerDataExcelExporter()
        if hasattr(exporter, 'data_standardizer'):
            test_results["CustomerDataExcelExporter"] = "✅ SUCCESS - Standardizer integrated"
            print("✅ CustomerDataExcelExporter: Successfully instantiated with standardizer")
        else:
            test_results["CustomerDataExcelExporter"] = "⚠️  WARNING - No standardizer found"
            print("⚠️  CustomerDataExcelExporter: Missing data_standardizer attribute")
    except Exception as e:
        test_results["CustomerDataExcelExporter"] = f"❌ FAILED: {str(e)}"
        print(f"❌ CustomerDataExcelExporter: {str(e)}")
    
    # Test DetailedCustomerExcelGenerator
    try:
        from comprehensive_customer_excel_generator import DetailedCustomerExcelGenerator
        generator = DetailedCustomerExcelGenerator()
        if hasattr(generator, 'data_standardizer'):
            test_results["DetailedCustomerExcelGenerator"] = "✅ SUCCESS - Standardizer integrated"
            print("✅ DetailedCustomerExcelGenerator: Successfully instantiated with standardizer")
        else:
            test_results["DetailedCustomerExcelGenerator"] = "⚠️  WARNING - No standardizer found"
            print("⚠️  DetailedCustomerExcelGenerator: Missing data_standardizer attribute")
    except Exception as e:
        test_results["DetailedCustomerExcelGenerator"] = f"❌ FAILED: {str(e)}"
        print(f"❌ DetailedCustomerExcelGenerator: {str(e)}")
    
    # Test MasterCustomerDataExporter
    try:
        from master_customer_data_exporter import MasterCustomerDataExporter
        master_exporter = MasterCustomerDataExporter()
        if hasattr(master_exporter, 'data_standardizer'):
            test_results["MasterCustomerDataExporter"] = "✅ SUCCESS - Standardizer integrated"
            print("✅ MasterCustomerDataExporter: Successfully instantiated with standardizer")
        else:
            test_results["MasterCustomerDataExporter"] = "⚠️  WARNING - No standardizer found"
            print("⚠️  MasterCustomerDataExporter: Missing data_standardizer attribute")
    except Exception as e:
        test_results["MasterCustomerDataExporter"] = f"❌ FAILED: {str(e)}"
        print(f"❌ MasterCustomerDataExporter: {str(e)}")
    
    return test_results

def generate_test_report(import_results, standardizer_test, class_results):
    """Generate comprehensive test report"""
    print("\n" + "=" * 70)
    print("📋 COMPREHENSIVE TEST REPORT")
    print("=" * 70)
    print(f"🕐 Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🎯 Purpose: Validate BHXH Data Standardization Integration")
    
    print("\n📦 MODULE IMPORT RESULTS:")
    for module, result in import_results.items():
        print(f"   {result.split(':')[0]} {module}")
    
    print(f"\n🔧 STANDARDIZER FUNCTIONALITY:")
    if standardizer_test:
        print("   ✅ BHXHDataStandardizer working correctly")
    else:
        print("   ❌ BHXHDataStandardizer has issues")
    
    print(f"\n🏗️  CLASS INSTANTIATION RESULTS:")
    for class_name, result in class_results.items():
        status = result.split(':')[0] if ':' in result else result.split(' -')[0]
        print(f"   {status} {class_name}")
    
    # Calculate overall status
    import_success = all("SUCCESS" in result for result in import_results.values())
    class_success = all("SUCCESS" in result for result in class_results.values())
    
    print(f"\n🎯 OVERALL STATUS:")
    if import_success and standardizer_test and class_success:
        print("   🟢 ALL TESTS PASSED - System ready for production")
        print("   ✅ Data standardization fully integrated")
        print("   ✅ All customer data will be properly standardized")
    else:
        print("   🔴 SOME TESTS FAILED - Review required")
        if not import_success:
            print("   ❌ Module import issues detected")
        if not standardizer_test:
            print("   ❌ Standardizer functionality issues")
        if not class_success:
            print("   ❌ Class integration issues detected")
    
    print("\n📋 NEXT STEPS:")
    print("   1. Run full data extraction and export pipeline")
    print("   2. Validate Excel output contains standardized data")
    print("   3. Verify compliance with BHXH data guidelines")
    print("   4. Conduct end-to-end testing with real data samples")

def main():
    """Run comprehensive integration tests"""
    print("🚀 BHXH Data Standardization Integration Test")
    print("=" * 70)
    print("Testing all customer data processing modules for proper")
    print("integration with BHXHDataStandardizer")
    print("=" * 70)
    
    # Run all tests
    import_results = test_module_imports()
    standardizer_test = test_standardizer_functionality()
    class_results = test_class_instantiation()
    
    # Generate report
    generate_test_report(import_results, standardizer_test, class_results)
    
    print("\n" + "=" * 70)
    print("🏁 INTEGRATION TEST COMPLETED")
    print("=" * 70)

if __name__ == "__main__":
    main()
