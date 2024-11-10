import pyshark
import sys
import time
from datetime import datetime
from collections import defaultdict
import json
from elevate import elevate
import logging
from typing import Dict, List, Optional
import pickle
import pandas as pd
import numpy as np
import os

class NetworkAnalyzer:
    def __init__(self, interface_name: str = None, output_file: str = 'network_data.json'): 
    # Get list of interfaces if none specified
        if interface_name is None:
            capture = pyshark.LiveCapture()
            interfaces = capture.interfaces
            print("Available interfaces:")
            for interface in interfaces:
                print(f"- {interface}")
            raise ValueError("Please specify an interface from the list above")
        
        self.interface_name = interface_name
        self.output_file = output_file
        
        # Add connection tracking if needed
        self.connection_tracking: Dict = defaultdict(lambda: {
            'start_time': None,
            'src_bytes': 0,
            'dst_bytes': 0,
            'src_pkts': 0,
            'dst_pkts': 0,
            'conn_state': '',
            'missed_bytes': 0
        })
        
        self.setup_logging()
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def get_service_from_port(self, port: int) -> str:
        # Define port mappings based on given service labels
        common_ports = {
            # DNS related ports
            53: 'dns',
            5353: 'dns',  # mDNS
            
            # HTTP related ports
            80: 'http',
            8080: 'http',
            8000: 'http',
            
            # FTP related ports
            20: 'ftp',
            21: 'ftp',
            
            # SSL/TLS ports
            443: 'ssl',
            8443: 'ssl',
            465: 'ssl',  # SMTPS
            993: 'ssl',  # IMAPS
            995: 'ssl',  # POP3S
            
            # GSSAPI related ports
            88: 'gssapi',  # Kerberos
            464: 'gssapi',  # Kerberos password change
            
            # DCE/RPC ports
            135: 'dce_rpc',  # Microsoft RPC
            593: 'dce_rpc',  # HTTP RPC
            
            # SMB related ports
            445: 'smb',
            139: 'smb',
        }
        
        # Special case for SMB with GSSAPI
        smb_gssapi_ports = {137, 138}  # NetBIOS ports often using both SMB and GSSAPI
        if port in smb_gssapi_ports:
            return 'smb;gssapi'
            
        # Return the mapped service or "-" for unknown
        return common_ports.get(port, '-')
    
    def extract_dns_info(self, packet) -> tuple:
        try:
            if hasattr(packet, 'dns'):
                query = packet.dns.qry_name if hasattr(packet.dns, 'qry_name') else ''
                qtype = packet.dns.qry_type if hasattr(packet.dns, 'qry_type') else ''
                return query, qtype
        except AttributeError:
            pass
        return '', ''

    def extract_ssl_info(self, packet) -> tuple:
        try:
            if hasattr(packet, 'ssl'):
                version = packet.ssl.record_version if hasattr(packet.ssl, 'record_version') else ''
                cipher = packet.ssl.cipher_suite if hasattr(packet.ssl, 'cipher_suite') else ''
                return version, cipher
        except AttributeError:
            pass
        return '', ''

    def extract_http_info(self, packet) -> tuple:
        try:
            if hasattr(packet, 'http'):
                method = packet.http.request_method if hasattr(packet.http, 'request_method') else ''
                uri = packet.http.request_uri if hasattr(packet.http, 'request_uri') else ''
                status = packet.http.response_code if hasattr(packet.http, 'response_code') else ''
                return method, uri, status
        except AttributeError:
            pass
        return '', '', ''

    def get_conn_state(self, packet) -> str:
        try:
            if hasattr(packet, 'tcp'):
                flags = packet.tcp.flags
                # S0: Connection attempt seen, no reply (Initial SYN without response)
                if flags == '0x0002':  # SYN
                    return 'S0'
                    
                # S1: Connection established, not terminated (SYN_ACK seen)
                elif flags == '0x0012':  # SYN-ACK
                    return 'S1'
                    
                # S2: Connection established and close attempt by originator seen
                elif flags == '0x0001' and hasattr(self, 'established_connection'):  # FIN after establishment
                    return 'S2'
                    
                # S3: Connection established and close attempt by responder seen
                elif flags == '0x0011' and hasattr(self, 'established_connection'):  # FIN-ACK after establishment
                    return 'S3'
                    
                # SF: Normal establishment and termination
                elif flags == '0x0010' and hasattr(self, 'established_connection'):  # Normal ACK in established connection
                    return 'SF'
                    
                # REJ: Connection attempt rejected
                elif flags == '0x0004' and not hasattr(self, 'established_connection'):  # RST without establishment
                    return 'REJ'
                    
                # RSTO: Connection established, originator aborted (sent RST)
                elif flags == '0x0004' and hasattr(self, 'established_connection'):  # RST after establishment
                    return 'RSTO'
                    
                # RSTR: Established, responder aborted
                elif flags == '0x0014':  # RST-ACK
                    return 'RSTR'
                    
                # RSTOS0: Originator sent RST after SYN
                elif flags == '0x0004' and hasattr(self, 'syn_sent'):
                    return 'RSTOS0'
                    
                # RSTRH: Responder sent RST after FIN
                elif flags == '0x0014' and hasattr(self, 'fin_received'):
                    return 'RSTRH'
                    
                # SH: Originator aborted (no FIN)
                elif flags == '0x0004' and hasattr(self, 'half_closed'):
                    return 'SH'
                    
                # SHR: Responder aborted (no FIN)
                elif flags == '0x0014' and hasattr(self, 'half_closed'):
                    return 'SHR'
                
                # OTH: No SYN seen, just midstream traffic
                else:
                    return 'OTH'
                    
            return 'OTH'  # Non-TCP traffic
            
        except AttributeError:
            return 'OTH'  # Any error cases

    def process_packet(self, packet) -> Optional[Dict]:
        try:
            if not (hasattr(packet, 'ip') and (hasattr(packet, 'tcp') or hasattr(packet, 'udp'))):
                return None

            # Basic connection information
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            
            if hasattr(packet, 'tcp'):
                proto = 'TCP'
                src_port = int(packet.tcp.srcport)
                dst_port = int(packet.tcp.dstport)
            else:
                proto = 'UDP'
                src_port = int(packet.udp.srcport)
                dst_port = int(packet.udp.dstport)

            # Create connection key
            conn_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
            
            # Update connection tracking
            if self.connection_tracking[conn_key]['start_time'] is None:
                self.connection_tracking[conn_key]['start_time'] = datetime.now()

            # Update packet counts and bytes
            self.connection_tracking[conn_key]['src_pkts'] += 1
            self.connection_tracking[conn_key]['src_bytes'] += int(packet.length)
            
            # Get additional protocol information
            dns_query, dns_qtype = self.extract_dns_info(packet)
            ssl_version, ssl_cipher = self.extract_ssl_info(packet)
            http_method, http_uri, http_status_code = self.extract_http_info(packet)

            # Calculate duration
            duration = (datetime.now() - self.connection_tracking[conn_key]['start_time']).total_seconds()

            # Prepare feature dictionary
            features = {
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'proto': proto,
                'service': self.get_service_from_port(dst_port),
                'duration': round(duration, 3),
                'src_bytes': self.connection_tracking[conn_key]['src_bytes'],
                'dst_bytes': self.connection_tracking[conn_key]['dst_bytes'],
                'conn_state': self.get_conn_state(packet),
                'missed_bytes': self.connection_tracking[conn_key]['missed_bytes'],
                'src_pkts': self.connection_tracking[conn_key]['src_pkts'],
                'dst_pkts': self.connection_tracking[conn_key]['dst_pkts'],
                'dns_query': dns_query,
                'dns_qtype': dns_qtype,
                'ssl_version': ssl_version,
                'ssl_cipher': ssl_cipher,
                'http_method': http_method,
                'http_uri': http_uri,
                'http_status_code': http_status_code,
                'weird_name': self.detect_weird_behavior(packet)
            }

            return features

        except Exception as e:
            self.logger.error(f"Error processing packet: {str(e)}")
            return None

    def detect_weird_behavior(self, packet) -> str:
        try:
            # High priority checks
            if hasattr(packet, 'tcp'):
                src_port = int(packet.tcp.srcport)
                dst_port = int(packet.tcp.dstport)
                flags = int(packet.tcp.flags, 16)
                
                # Check for connection initialization anomalies
                if flags & 0x12:  # SYN-ACK flags
                    return 'connection_originator_SYN_ack'
                
                # Check for inappropriate FIN flags in relation to connection state
                if flags & 0x01 and not hasattr(self, 'established_connection'):
                    return 'inappropriate_FIN'
                
                # Check for data transfer before connection establishment
                if not (flags & 0x02) and hasattr(packet, 'payload'):
                    return 'data_before_established'
                
                # Check for connection reuse patterns
                if hasattr(self, 'previous_connection') and flags & 0x02:
                    return 'active_connection_reuse'

            # DNS specific checks
            if hasattr(packet, 'dns'):
                if hasattr(packet.dns, 'rr_type') and packet.dns.rr_type not in self.known_rr_types:
                    return 'DNS_RR_unknown_type'

            # Checksum validations
            if hasattr(packet, 'tcp'):
                if not self._validate_tcp_checksum(packet):
                    return 'bad_TCP_checksum'
            if hasattr(packet, 'udp'):
                if not self._validate_udp_checksum(packet):
                    return 'bad_UDP_checksum'

            # DNP3 protocol checks
            if hasattr(packet, 'dnp3'):
                if not self._validate_dnp3_header_checksum(packet):
                    return 'dnp3_corrupt_header_checksum'

            # TCP sequence and acknowledgment checks
            if hasattr(packet, 'tcp'):
                if self._check_sequence_hole(packet):
                    return 'above_hole_data_without_any_acks'

            # Routing anomaly detection
            if hasattr(packet, 'ip'):
                if self._detect_split_routing(packet):
                    return 'possible_split_routing'

            # If no anomaly is detected, return normal behavior indicator
            return '-'

        except Exception as e:
            self.logger.error(f"Error in weird behavior detection: {str(e)}")
            return '-'  # Return normal behavior indicator on error

        # If no specific condition is met
        return '-'
    def start_capture(self):
        try:
            elevate(graphical=False)
            
            self.logger.info(f"Starting capture on interface: {self.interface_name}")
            capture = pyshark.LiveCapture(interface=self.interface_name)

            for packet in capture.sniff_continuously():
                features = self.process_packet(packet)
                if features:
                    # Save to file
                    with open(self.output_file, 'a') as f:
                        json.dump(features, f)
                        f.write('\n')
                    
                    # Print summary
                    self.logger.info(
                        f"Captured: {features['proto']} {features['src_ip']}:{features['src_port']} -> "
                        f"{features['dst_ip']}:{features['dst_port']} ({features['service']})"
                    )

        except KeyboardInterrupt:
            self.logger.info("\nCapture stopped by user")
        except Exception as e:
            self.logger.error(f"Capture error: {str(e)}")
            sys.exit(1)


class MLNetworkAnalyzer(NetworkAnalyzer):
    def __init__(self,
                 interface_name: str,
                 pipeline_path: str,
                 output_file: str = 'network_data.json',
                 prediction_file: str = 'predictions.json'):
        super().__init__(interface_name, output_file)
        self.pipeline_path = pipeline_path
        self.prediction_file = prediction_file
        self.load_pipeline()

        # Define feature columns, mappings, etc.
        # ... your initialization code

    def load_pipeline(self):
        """Load the saved pipeline components"""
        try:
            # Get the current directory of the script
            current_dir = os.path.dirname(os.path.abspath(__file__))

            # Construct the absolute path for the pipeline file
            pipeline_path = os.path.join(current_dir, '..', 'pipeline.pkl')

            # Load the pipeline components
            with open(pipeline_path, 'rb') as f:
                pipeline_components = pickle.load(f)

            # Extract components from the pipeline
            self.scaler = pipeline_components['scaler']
            self.label_encoder_src_ip = pipeline_components['label_encoder_src_ip']
            self.label_encoder_dst_ip = pipeline_components['label_encoder_dst_ip']
            self.target_encoder = pipeline_components['target_encoder']
            self.model = pipeline_components['model']

            self.logger.info("Successfully loaded ML pipeline components")
        except Exception as e:
            self.logger.error(f"Error loading pipeline: {str(e)}")
            raise
def load_pipeline(self):
    try:
        # Get the current directory of the script
        current_dir = os.path.dirname(os.path.abspath(__file__))

        # Construct the absolute path for the pipeline file
        pipeline_path = os.path.join(current_dir, '..', 'pipeline.pkl')

        # Load the pipeline components
        with open(pipeline_path, 'rb') as f:
            pipeline_components = pickle.load(f)

        # Extract components from the pipeline
        self.scaler = pipeline_components['scaler']
        self.label_encoder_src_ip = pipeline_components['label_encoder_src_ip']
        self.label_encoder_dst_ip = pipeline_components['label_encoder_dst_ip']
        self.target_encoder = pipeline_components['target_encoder']
        self.model = pipeline_components['model']

        self.logger.info("Successfully loaded ML pipeline components")
    except Exception as e:
        self.logger.error(f"Error loading pipeline: {str(e)}")
        raise

    def apply_mappings(self, df: pd.DataFrame) -> pd.DataFrame:
        """Apply all the custom mappings to the DataFrame"""
        try:
            # Apply mappings with default values for unknown categories
            df['proto'] = df['proto'].apply(lambda x: self.proto_mapping.get(x.lower() if isinstance(x, str) else x, 0))
            df['service'] = df['service'].apply(lambda x: self.service_mapping.get(x, 0))
            df['http_method'] = df['http_method'].apply(lambda x: self.http_method_mapping.get(x, 0))
            df['conn_state'] = df['conn_state'].apply(lambda x: self.conn_state_mapping.get(x, 0))

            return df
        except Exception as e:
            self.logger.error(f"Error in applying mappings: {str(e)}")
            return df

    def preprocess_features(self, features: Dict) -> pd.DataFrame:
        """Preprocess a single feature dictionary using the pipeline components"""
        try:
            # Convert single dictionary to DataFrame
            df = pd.DataFrame([features])

            # Ensure all expected columns are present
            for col in self.feature_columns:
                if col not in df.columns:
                    df[col] = '-'

            # Apply custom mappings
            df = self.apply_mappings(df)

            # Apply label encoding to IP addresses
            df['src_ip'] = self.label_encoder_src_ip.transform([str(ip) for ip in df['src_ip']])
            df['dst_ip'] = self.label_encoder_dst_ip.transform([str(ip) for ip in df['dst_ip']])

            # Apply target encoding to categorical columns
            df = self.target_encoder.transform(df)

            # Scale numeric features
            numeric_columns = ['src_port', 'dst_port', 'duration', 'src_bytes',
                               'dst_bytes', 'src_pkts', 'dst_pkts', 'missed_bytes']
            df[numeric_columns] = self.scaler.transform(df[numeric_columns])

            return df

        except Exception as e:
            self.logger.error(f"Error in preprocessing: {str(e)}")
            return None

    def get_prediction_label(self, prediction_index: int) -> str:
        """Convert numerical prediction back to label"""
        reverse_mapping = {v: k for k, v in self.target_mapping.items()}
        return reverse_mapping.get(prediction_index, 'unknown')

    def process_packet(self, packet) -> Optional[Dict]:
        """Override parent's process_packet to include ML prediction"""
        features = super().process_packet(packet)

        if features:
            try:
                # Preprocess features
                processed_df = self.preprocess_features(features)

                if processed_df is not None:
                    # Make prediction
                    prediction = self.model.predict(processed_df)[0]
                    prediction_proba = self.model.predict_proba(processed_df)[0]

                    # Get prediction label
                    prediction_label = self.get_prediction_label(prediction)

                    # Add prediction to features
                    features['prediction'] = prediction_label
                    features['prediction_index'] = int(prediction)
                    features['confidence'] = float(max(prediction_proba))

                    # Save prediction
                    with open(self.prediction_file, 'a') as f:
                        json.dump({
                            'timestamp': datetime.now().isoformat(),
                            'features': features,
                            'prediction': prediction_label,
                            'prediction_index': int(prediction),
                            'confidence': float(max(prediction_proba))
                        }, f)
                        f.write('\n')

                    # Log prediction if confidence is high or prediction indicates attack
                    if features['confidence'] > 0.8 or features['prediction_index'] != 0:
                        self.logger.warning(
                            f"High confidence prediction: {prediction_label} "
                            f"(confidence: {features['confidence']:.2f}) "
                            f"for connection {features['src_ip']}:{features['src_port']} -> "
                            f"{features['dst_ip']}:{features['dst_port']}"
                        )

            except Exception as e:
                self.logger.error(f"Error in ML processing: {str(e)}")
                self.logger.exception("Full traceback:")

        return features

    def start_capture(self):
        """Override start_capture to add initialization logging"""
        self.logger.info("Starting ML-enabled network capture...")
        self.logger.info("Loaded mappings for:")
        self.logger.info(f"- {len(self.proto_mapping)} protocol types")
        self.logger.info(f"- {len(self.service_mapping)} services")
        self.logger.info(f"- {len(self.http_method_mapping)} HTTP methods")
        self.logger.info(f"- {len(self.conn_state_mapping)} connection states")
        super().start_capture()

def main():
    # Initialize and start the ML-enabled analyzer
    current_dir = os.path.dirname(os.path.abspath(__file__))
    pipeline_path = os.path.join(current_dir, '..', 'pipeline.pkl')

    analyzer = MLNetworkAnalyzer(
        interface_name='eth0',  # Change to your interface
        pipeline_path=pipeline_path,  # Change to your pipeline path
        output_file='./network_data.json',
        prediction_file='./predictions.json'
    )
    analyzer.start_capture()

if __name__ == "__main__":
    main()