import sys,unittest
from pathlib import Path
from datetime import datetime,timedelta,timezone
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'integrations'))
from logai_anomaly import features
class Features(unittest.TestCase):
    def test_chronological_split_and_unseen(self):
        start=datetime(2026,1,1,tzinfo=timezone.utc)
        rows=[{'id':str(i),'timestamp':(start+timedelta(minutes=i)).isoformat(),'sender':'known' if i<35 else 'new','action':'send'} for i in range(50)]
        ids,train,test=features(list(reversed(rows)))
        self.assertEqual(len(train),35);self.assertEqual(ids[0],'35');self.assertEqual(test[0][1],0)
    def test_insufficient_data(self):
        with self.assertRaises(ValueError):features([])
if __name__=='__main__':unittest.main()
