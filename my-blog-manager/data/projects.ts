// 项目数据文件

export type Project = {
  id: string;
  name: string;
  description: string;
  icon: string;
  githubUrl: string;
  tags: string[];
};

export const projectsData: Project[] = [
  {
    "id": "proj_1775049332705",
    "name": "CTF Tools Collection",
    "githubUrl": "https://github.com/kings-well-byte",
    "description": "个人CTF工具集，包含PWN、Web渗透测试常用脚本和工具，持续更新中...",
    "icon": "🚀",
    "tags": [
      "PWN",
      "Web"
    ]
  },
];
