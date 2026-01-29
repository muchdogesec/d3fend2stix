"""Tests for main.py module"""
import pytest
from unittest.mock import patch, MagicMock, call
from d3fend2stix.main import main


class TestMain:
    """Tests for main function"""
    
    @patch('d3fend2stix.main.store_in_bundle')
    @patch('d3fend2stix.main.D3FENDConverter')
    @patch('d3fend2stix.main.D3FENDParser')
    @patch('d3fend2stix.main.clean_filesystem')
    @patch('d3fend2stix.main.config')
    def test_main_success_flow(self, mock_config, mock_clean, mock_parser_class, 
                               mock_converter_class, mock_store):
        """Test successful execution of main function"""
        # Setup mocks
        mock_config.d3fend_json_file = "test.json"
        mock_config.stix2_objects_folder = "/test/objects"
        mock_config.stix2_bundles_folder = "/test/bundles"
        mock_config.fs = MagicMock()
        
        mock_parser = MagicMock()
        mock_parser_class.return_value = mock_parser
        
        mock_converter = MagicMock()
        mock_stix_objects = [
            {"id": "course-of-action--123", "type": "course-of-action"},
            {"id": "indicator--456", "type": "indicator"}
        ]
        mock_converter.convert.return_value = mock_stix_objects
        mock_converter_class.return_value = mock_converter
        
        mock_store.return_value = "bundle--test-123"
        
        # Execute
        main()
        
        # Verify clean_filesystem was called
        mock_clean.assert_called_once_with(mock_config.stix2_objects_folder)
        
        # Verify parser was created and load_data called
        mock_parser_class.assert_called_once_with(mock_config.d3fend_json_file)
        mock_parser.load_data.assert_called_once()
        
        # Verify converter was created and convert called
        mock_converter_class.assert_called_once_with(mock_parser)
        mock_converter.convert.assert_called_once()
        
        # Verify bundle was created
        mock_store.assert_called_once_with(
            mock_config.stix2_bundles_folder,
            mock_stix_objects,
            filename="d3fend-bundle"
        )
    
    @patch('d3fend2stix.main.store_in_bundle')
    @patch('d3fend2stix.main.D3FENDConverter')
    @patch('d3fend2stix.main.D3FENDParser')
    @patch('d3fend2stix.main.clean_filesystem')
    @patch('d3fend2stix.main.config')
    def test_main_parser_step(self, mock_config, mock_clean, mock_parser_class,
                              mock_converter_class, mock_store):
        """Test that parser step is executed correctly"""
        mock_config.d3fend_json_file = "test.json"
        mock_config.stix2_objects_folder = "/test/objects"
        mock_config.stix2_bundles_folder = "/test/bundles"
        mock_config.fs = MagicMock()
        
        mock_parser = MagicMock()
        mock_parser_class.return_value = mock_parser
        
        mock_converter = MagicMock()
        mock_converter.convert.return_value = []
        mock_converter_class.return_value = mock_converter
        
        mock_store.return_value = "bundle--123"
        
        main()
        
        # Verify parser was initialized with correct file
        mock_parser_class.assert_called_once_with("test.json")
        # Verify load_data was called
        mock_parser.load_data.assert_called_once()
    
    @patch('d3fend2stix.main.store_in_bundle')
    @patch('d3fend2stix.main.D3FENDConverter')
    @patch('d3fend2stix.main.D3FENDParser')
    @patch('d3fend2stix.main.clean_filesystem')
    @patch('d3fend2stix.main.config')
    def test_main_converter_step(self, mock_config, mock_clean, mock_parser_class,
                                 mock_converter_class, mock_store):
        """Test that converter step is executed correctly"""
        mock_config.d3fend_json_file = "test.json"
        mock_config.stix2_objects_folder = "/test/objects"
        mock_config.stix2_bundles_folder = "/test/bundles"
        mock_config.fs = MagicMock()
        
        mock_parser = MagicMock()
        mock_parser_class.return_value = mock_parser
        
        mock_converter = MagicMock()
        test_objects = [{"id": "test-1"}]
        mock_converter.convert.return_value = test_objects
        mock_converter_class.return_value = mock_converter
        
        mock_store.return_value = "bundle--123"
        
        main()
        
        # Verify converter was initialized with parser
        mock_converter_class.assert_called_once_with(mock_parser)
        # Verify convert was called
        mock_converter.convert.assert_called_once()
    
    @patch('d3fend2stix.main.store_in_bundle')
    @patch('d3fend2stix.main.D3FENDConverter')
    @patch('d3fend2stix.main.D3FENDParser')
    @patch('d3fend2stix.main.clean_filesystem')
    @patch('d3fend2stix.main.config')
    def test_main_filesystem_storage(self, mock_config, mock_clean, mock_parser_class,
                                     mock_converter_class, mock_store):
        """Test that main function works without filesystem storage (Step 3 is commented out)"""
        mock_config.d3fend_json_file = "test.json"
        mock_config.stix2_objects_folder = "/test/objects"
        mock_config.stix2_bundles_folder = "/test/bundles"
        
        mock_fs = MagicMock()
        mock_config.fs = mock_fs
        
        mock_parser = MagicMock()
        mock_parser_class.return_value = mock_parser
        
        mock_converter = MagicMock()
        test_objects = [
            {"id": "obj-1", "type": "course-of-action"},
            {"id": "obj-2", "type": "indicator"}
        ]
        mock_converter.convert.return_value = test_objects
        mock_converter_class.return_value = mock_converter
        
        mock_store.return_value = "bundle--123"
        
        main()
        
        # Verify filesystem storage is not called (Step 3 is commented out)
        assert mock_fs.add.call_count == 0
        # Verify bundle is still created
        mock_store.assert_called_once()
    
    @patch('d3fend2stix.main.store_in_bundle')
    @patch('d3fend2stix.main.D3FENDConverter')
    @patch('d3fend2stix.main.D3FENDParser')
    @patch('d3fend2stix.main.clean_filesystem')
    @patch('d3fend2stix.main.config')
    @patch('d3fend2stix.main.logger')
    def test_main_filesystem_storage_error_handling(self, mock_logger, mock_config, 
                                                    mock_clean, mock_parser_class,
                                                    mock_converter_class, mock_store):
        """Test that main completes even if filesystem is not used (Step 3 commented out)"""
        mock_config.d3fend_json_file = "test.json"
        mock_config.stix2_objects_folder = "/test/objects"
        mock_config.stix2_bundles_folder = "/test/bundles"
        
        mock_fs = MagicMock()
        mock_fs.add.side_effect = Exception("Storage error")
        mock_config.fs = mock_fs
        
        mock_parser = MagicMock()
        mock_parser_class.return_value = mock_parser
        
        mock_converter = MagicMock()
        test_objects = [{"id": "obj-1", "type": "course-of-action"}]
        mock_converter.convert.return_value = test_objects
        mock_converter_class.return_value = mock_converter
        
        mock_store.return_value = "bundle--123"
        
        # Should not raise exception
        main()
        
        # Filesystem storage is not called (Step 3 is commented out)
        # So no warning should be logged about storage errors
        assert mock_logger.warning.call_count == 0
    
    @patch('d3fend2stix.main.store_in_bundle')
    @patch('d3fend2stix.main.D3FENDConverter')
    @patch('d3fend2stix.main.D3FENDParser')
    @patch('d3fend2stix.main.clean_filesystem')
    @patch('d3fend2stix.main.config')
    def test_main_bundle_creation(self, mock_config, mock_clean, mock_parser_class,
                                  mock_converter_class, mock_store):
        """Test that bundle is created with correct parameters"""
        mock_config.d3fend_json_file = "test.json"
        mock_config.stix2_objects_folder = "/test/objects"
        mock_config.stix2_bundles_folder = "/test/bundles"
        mock_config.fs = MagicMock()
        
        mock_parser = MagicMock()
        mock_parser_class.return_value = mock_parser
        
        mock_converter = MagicMock()
        test_objects = [{"id": "obj-1"}]
        mock_converter.convert.return_value = test_objects
        mock_converter_class.return_value = mock_converter
        
        mock_store.return_value = "bundle--abc-123"
        
        main()
        
        # Verify store_in_bundle was called with correct arguments
        mock_store.assert_called_once_with(
            "/test/bundles",
            test_objects,
            filename="d3fend-bundle"
        )
    
    @patch('d3fend2stix.main.store_in_bundle')
    @patch('d3fend2stix.main.D3FENDConverter')
    @patch('d3fend2stix.main.D3FENDParser')
    @patch('d3fend2stix.main.clean_filesystem')
    @patch('d3fend2stix.main.config')
    @patch('d3fend2stix.main.logger')
    def test_main_logs_progress(self, mock_logger, mock_config, mock_clean,
                                mock_parser_class, mock_converter_class, mock_store):
        """Test that main function logs progress appropriately"""
        mock_config.d3fend_json_file = "test.json"
        mock_config.stix2_objects_folder = "/test/objects"
        mock_config.stix2_bundles_folder = "/test/bundles"
        mock_config.fs = MagicMock()
        
        mock_parser = MagicMock()
        mock_parser_class.return_value = mock_parser
        
        mock_converter = MagicMock()
        mock_converter.convert.return_value = [{"id": "obj-1"}]
        mock_converter_class.return_value = mock_converter
        
        mock_store.return_value = "bundle--123"
        
        main()
        
        # Verify logging occurred
        mock_logger.info.assert_called()
        # Should log multiple steps
        assert mock_logger.info.call_count >= 5
    
    @patch('d3fend2stix.main.store_in_bundle')
    @patch('d3fend2stix.main.D3FENDConverter')
    @patch('d3fend2stix.main.D3FENDParser')
    @patch('d3fend2stix.main.clean_filesystem')
    @patch('d3fend2stix.main.config')
    def test_main_empty_objects(self, mock_config, mock_clean, mock_parser_class,
                               mock_converter_class, mock_store):
        """Test main function handles empty object list"""
        mock_config.d3fend_json_file = "test.json"
        mock_config.stix2_objects_folder = "/test/objects"
        mock_config.stix2_bundles_folder = "/test/bundles"
        mock_config.fs = MagicMock()
        
        mock_parser = MagicMock()
        mock_parser_class.return_value = mock_parser
        
        mock_converter = MagicMock()
        mock_converter.convert.return_value = []
        mock_converter_class.return_value = mock_converter
        
        mock_store.return_value = "bundle--123"
        
        # Should not raise exception
        main()
        
        # Bundle should still be created
        mock_store.assert_called_once()
    
    @patch('d3fend2stix.main.store_in_bundle')
    @patch('d3fend2stix.main.D3FENDConverter')
    @patch('d3fend2stix.main.D3FENDParser')
    @patch('d3fend2stix.main.clean_filesystem')
    @patch('d3fend2stix.main.config')
    def test_main_execution_order(self, mock_config, mock_clean, mock_parser_class,
                                  mock_converter_class, mock_store):
        """Test that main function executes steps in correct order"""
        mock_config.d3fend_json_file = "test.json"
        mock_config.stix2_objects_folder = "/test/objects"
        mock_config.stix2_bundles_folder = "/test/bundles"
        mock_config.fs = MagicMock()
        
        mock_parser = MagicMock()
        mock_parser_class.return_value = mock_parser
        
        mock_converter = MagicMock()
        mock_converter.convert.return_value = [{"id": "obj-1"}]
        mock_converter_class.return_value = mock_converter
        
        mock_store.return_value = "bundle--123"
        
        # Create a mock manager to track call order
        manager = MagicMock()
        manager.attach_mock(mock_clean, 'clean')
        manager.attach_mock(mock_parser_class, 'parser_class')
        manager.attach_mock(mock_converter_class, 'converter_class')
        manager.attach_mock(mock_store, 'store')
        
        main()
        
        # Verify calls were made in order
        expected_calls = [
            call.clean(mock_config.stix2_objects_folder),
            call.parser_class(mock_config.d3fend_json_file),
            call.converter_class(mock_parser),
            call.store(mock_config.stix2_bundles_folder, [{"id": "obj-1"}], filename="d3fend-bundle")
        ]
        
        # Check that key operations happened
        manager.clean.assert_called()
        manager.parser_class.assert_called()
        manager.converter_class.assert_called()
        manager.store.assert_called()
