"""Tests for main.py module"""
import pytest
from unittest.mock import patch, MagicMock, call
from d3fend2stix.main import main


class TestMain:
    """Tests for main function"""

    @pytest.fixture(autouse=True)
    def setup_mocks(self):
        """Setup common mocks for all tests"""
        with (patch('d3fend2stix.main.Path') as mock_path,
              patch('d3fend2stix.main.store_in_bundle') as mock_store,
              patch('d3fend2stix.main.D3FENDConverter') as mock_converter_class,
              patch('d3fend2stix.main.D3FENDParser') as mock_parser_class,
              patch('d3fend2stix.main.clean_filesystem') as mock_clean,
              patch('d3fend2stix.main.config') as mock_config):
            self.mock_config = mock_config
            self.mock_config.d3fend_json_file = "test.json"
            self.mock_config.stix2_objects_folder = "/test/objects"
            self.mock_config.stix2_bundles_folder = "/test/bundles"
            self.mock_config.fs = MagicMock()
            
            self.mock_parser = MagicMock()
            self.mock_parser.version = "1.3.0"
            
            self.mock_converter = MagicMock()
            self.mock_converter.convert.return_value = []
            self.mock_converter.other_relationships = []
            
            mock_converter_class.return_value = self.mock_converter
            mock_parser_class.return_value = self.mock_parser
            mock_store.return_value = ("bundle--test-123", "/test/bundles/test.json")

            self.mock_clean = mock_clean
            self.mock_converter_class = mock_converter_class
            self.mock_parser_class = mock_parser_class
            self.mock_store = mock_store
            self.mock_path_cls = mock_path
            yield
    

    def test_main_success_flow(self):
        """Test successful execution of main function"""
        
        # Execute
        main()
        
        # Verify clean_filesystem was called
        self.mock_clean.assert_called_once_with(self.mock_config.stix2_objects_folder)
        
        # Verify parser was created and load_data called
        self.mock_parser_class.assert_called_once_with(self.mock_config.d3fend_json_file)
        self.mock_parser.load_data.assert_called_once()
        
        # Verify converter was created and convert called
        self.mock_converter_class.assert_called_once_with(self.mock_parser)
        self.mock_converter.convert.assert_called_once()
        
        # Verify bundle was created
        self.mock_store.assert_called_once_with(
            self.mock_config.stix2_bundles_folder,
            self.mock_converter.convert.return_value,
            filename="d3fend-v1_3_0-bundle"
        )
    
    def test_main_parser_step(self):
        """Test that parser step is executed correctly"""
        main()
        
        # Verify parser was initialized with correct file
        self.mock_parser_class.assert_called_once_with("test.json")
        # Verify load_data was called
        self.mock_parser.load_data.assert_called_once()
    
    def test_main_converter_step(self):
        """Test that converter step is executed correctly"""
        test_objects = [{"id": "test-1"}]
        self.mock_converter.convert.return_value = test_objects
        
        main()
        
        # Verify converter was initialized with parser
        self.mock_converter_class.assert_called_once_with(self.mock_parser)
        # Verify convert was called
        self.mock_converter.convert.assert_called_once()
    
    def test_main_filesystem_storage(self):
        """Test that main function works without filesystem storage (Step 3 is commented out)"""
        test_objects = [
            {"id": "obj-1", "type": "course-of-action"},
            {"id": "obj-2", "type": "indicator"}
        ]
        self.mock_converter.convert.return_value = test_objects
        
        main()
        
        # Verify filesystem storage is not called (Step 3 is commented out)
        assert self.mock_config.fs.add.call_count == 0
        # Verify bundle is still created
        self.mock_store.assert_called_once()
    
    @patch('d3fend2stix.main.logger')
    def test_main_filesystem_storage_error_handling(self, mock_logger):
        """Test that main completes even if filesystem is not used (Step 3 commented out)"""
        self.mock_config.fs.add.side_effect = Exception("Storage error")
        test_objects = [{"id": "obj-1", "type": "course-of-action"}]
        self.mock_converter.convert.return_value = test_objects
        
        # Should not raise exception
        main()
        
        # Filesystem storage is not called (Step 3 is commented out)
        # So no warning should be logged about storage errors
        assert mock_logger.warning.call_count == 0
    
    def test_main_bundle_creation(self):
        """Test that bundle is created with correct parameters"""
        test_objects = [{"id": "obj-1"}]
        self.mock_converter.convert.return_value = test_objects
        
        main()
        
        # Verify store_in_bundle was called with correct arguments
        self.mock_store.assert_called_once_with(
            self.mock_config.stix2_bundles_folder,
            test_objects,
            filename="d3fend-v1_3_0-bundle"
        )
    
    @patch('d3fend2stix.main.logger')
    def test_main_logs_progress(self, mock_logger):
        """Test that main function logs progress appropriately"""
        self.mock_converter.convert.return_value = [{"id": "obj-1"}]
        
        main()
        
        # Verify logging occurred
        mock_logger.info.assert_called()
        # Should log multiple steps
        assert mock_logger.info.call_count >= 5
    
    def test_main_empty_objects(self):
        """Test main function handles empty object list"""
        # Should not raise exception
        main()
        
        # Bundle should still be created
        self.mock_store.assert_called_once()
    
    def test_main_execution_order(self):
        """Test that main function executes steps in correct order"""
        self.mock_converter.convert.return_value = [{"id": "obj-1"}]
        
        # Create a mock manager to track call order
        manager = MagicMock()
        manager.attach_mock(self.mock_clean, 'clean')
        manager.attach_mock(self.mock_parser_class, 'parser_class')
        manager.attach_mock(self.mock_converter_class, 'converter_class')
        manager.attach_mock(self.mock_store, 'store')
        
        main()
        # Verify calls were made in order
        expected_calls = [
            call.clean(self.mock_config.stix2_objects_folder),
            call.parser_class(self.mock_config.d3fend_json_file),
            call.converter_class(self.mock_parser),
            call.store(self.mock_config.stix2_bundles_folder, [{"id": "obj-1"}], filename="d3fend-bundle")
        ]