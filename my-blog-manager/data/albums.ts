// 馃洝锔?鏈枃浠剁敱 XingHuiSama 鎺у埗鍙拌嚜鍔ㄧ敓鎴愶紝璇峰嬁鎵嬪姩淇敼
export interface Photo { url: string; caption?: string; }
export interface Album { id: string; title: string; description: string; cover: string; date: string; photos: Photo[]; }

export const albums: Album[] = [
  {
    "id": "terra-journey",
    "title": "娉版媺澶ч檰绾",
    "description": "鍏充簬婧愮煶銆佸鏄熶笌鍓嶆枃鏄庣殑瑙嗚璁板綍锛堟祴璇曠敤鐩稿唽锛?,
    "cover": "https://bu.dusays.com/2026/03/24/69c24230de927.jpg",
    "date": "2026.01",
    "photos": [
      {
        "url": "https://bu.dusays.com/2026/03/31/69cb69bb530d8.jpg",
        "caption": "鍘熸潵鐨勪汉"
      },
      {
        "url": "https://bu.dusays.com/2026/03/24/69c24230de927.jpg",
        "caption": "鏄熺┖婕父"
      }
    ]
  },
  {
    "id": "history-tour",
    "title": "鍞愬畫鍘嗗彶宸℃父",
    "description": "瀵昏鍗冨勾鍓嶇殑闀垮畨涓庢贝姊侀仐杩癸紙娴嬭瘯鐢ㄧ浉鍐岋級",
    "cover": "https://bu.dusays.com/2026/03/24/69c24230a4efe.jpg",
    "date": "2025.10",
    "photos": [
      {
        "url": "https://bu.dusays.com/2026/03/24/69c24230a5ff8.jpg",
        "caption": "鍙ら兘澶曢槼"
      },
      {
        "url": "https://bu.dusays.com/2026/03/24/69c24230d661d.jpg",
        "caption": "闈掔煶鏉垮皬璺?
      },
      {
        "url": "https://bu.dusays.com/2026/03/24/69c24230de927.jpg",
        "caption": "椋炴獝缈樿"
      }
    ]
  }
];
