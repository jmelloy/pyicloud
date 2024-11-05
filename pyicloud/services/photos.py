"""Photo service."""

import json
import base64
from urllib.parse import urlencode

from datetime import datetime, timezone
from pyicloud.exceptions import PyiCloudServiceNotActivatedException
from pyicloud.utils import BPListReader


class PhotoLibrary:
    """Represents a library in the user's photos.

    This provides access to all the albums as well as the photos.
    """

    SMART_FOLDERS = {
        "All Photos": {
            "obj_type": "CPLAssetByAssetDateWithoutHiddenOrDeleted",
            "list_type": "CPLAssetAndMasterByAssetDateWithoutHiddenOrDeleted",
            "direction": "ASCENDING",
            "query_filter": None,
        },
        "Time-lapse": {
            "obj_type": "CPLAssetInSmartAlbumByAssetDate:Timelapse",
            "list_type": "CPLAssetAndMasterInSmartAlbumByAssetDate",
            "direction": "ASCENDING",
            "query_filter": [
                {
                    "fieldName": "smartAlbum",
                    "comparator": "EQUALS",
                    "fieldValue": {"type": "STRING", "value": "TIMELAPSE"},
                }
            ],
        },
        "Videos": {
            "obj_type": "CPLAssetInSmartAlbumByAssetDate:Video",
            "list_type": "CPLAssetAndMasterInSmartAlbumByAssetDate",
            "direction": "ASCENDING",
            "query_filter": [
                {
                    "fieldName": "smartAlbum",
                    "comparator": "EQUALS",
                    "fieldValue": {"type": "STRING", "value": "VIDEO"},
                }
            ],
        },
        "Slo-mo": {
            "obj_type": "CPLAssetInSmartAlbumByAssetDate:Slomo",
            "list_type": "CPLAssetAndMasterInSmartAlbumByAssetDate",
            "direction": "ASCENDING",
            "query_filter": [
                {
                    "fieldName": "smartAlbum",
                    "comparator": "EQUALS",
                    "fieldValue": {"type": "STRING", "value": "SLOMO"},
                }
            ],
        },
        "Bursts": {
            "obj_type": "CPLAssetBurstStackAssetByAssetDate",
            "list_type": "CPLBurstStackAssetAndMasterByAssetDate",
            "direction": "ASCENDING",
            "query_filter": None,
        },
        "Favorites": {
            "obj_type": "CPLAssetInSmartAlbumByAssetDate:Favorite",
            "list_type": "CPLAssetAndMasterInSmartAlbumByAssetDate",
            "direction": "ASCENDING",
            "query_filter": [
                {
                    "fieldName": "smartAlbum",
                    "comparator": "EQUALS",
                    "fieldValue": {"type": "STRING", "value": "FAVORITE"},
                }
            ],
        },
        "Panoramas": {
            "obj_type": "CPLAssetInSmartAlbumByAssetDate:Panorama",
            "list_type": "CPLAssetAndMasterInSmartAlbumByAssetDate",
            "direction": "ASCENDING",
            "query_filter": [
                {
                    "fieldName": "smartAlbum",
                    "comparator": "EQUALS",
                    "fieldValue": {"type": "STRING", "value": "PANORAMA"},
                }
            ],
        },
        "Portrait": {
            "obj_type": "CPLAssetInSmartAlbumByAssetDate:Portrait",
            "list_type": "CPLAssetAndMasterInSmartAlbumByAssetDate",
            "direction": "ASCENDING",
            "query_filter": [
                {
                    "fieldName": "smartAlbum",
                    "comparator": "EQUALS",
                    "fieldValue": {"type": "STRING", "value": "DEPTH"},
                }
            ],
        },
        "Screenshots": {
            "obj_type": "CPLAssetInSmartAlbumByAssetDate:Screenshot",
            "list_type": "CPLAssetAndMasterInSmartAlbumByAssetDate",
            "direction": "ASCENDING",
            "query_filter": [
                {
                    "fieldName": "smartAlbum",
                    "comparator": "EQUALS",
                    "fieldValue": {"type": "STRING", "value": "SCREENSHOT"},
                }
            ],
        },
        "Live": {
            "obj_type": "CPLAssetInSmartAlbumByAssetDate:Live",
            "list_type": "CPLAssetAndMasterInSmartAlbumByAssetDate",
            "direction": "ASCENDING",
            "query_filter": [
                {
                    "fieldName": "smartAlbum",
                    "comparator": "EQUALS",
                    "fieldValue": {"type": "STRING", "value": "LIVE"},
                }
            ],
        },
        "Recently Deleted": {
            "obj_type": "CPLAssetDeletedByExpungedDate",
            "list_type": "CPLAssetAndMasterDeletedByExpungedDate",
            "direction": "ASCENDING",
            "query_filter": None,
        },
        "Hidden": {
            "obj_type": "CPLAssetHiddenByAssetDate",
            "list_type": "CPLAssetAndMasterHiddenByAssetDate",
            "direction": "ASCENDING",
            "query_filter": None,
        },
    }

    def __init__(self, service, zone_id, shared=False):
        self.service = service
        self.zone_id = zone_id
        self.shared = shared

        self._albums = None

        url = f"{self.service.service_endpoint(shared)}/records/query?{urlencode(self.service.params)}"

        json_data = json.dumps(
            {"query": {"recordType": "CheckIndexingState"}, "zoneID": self.zone_id}
        )
        request = self.service.session.post(
            url, data=json_data, headers={"Content-type": "text/plain"}
        )
        response = request.json()
        indexing_state = response["records"][0]["fields"]["state"]["value"]
        if indexing_state != "FINISHED":
            raise PyiCloudServiceNotActivatedException(
                "iCloud Photo Library not finished indexing. "
                "Please try again in a few minutes."
            )

    @property
    def albums(self):
        """Returns photo albums."""
        if not self._albums:
            self._albums = {
                name: PhotoAlbum(
                    self.service,
                    name,
                    zone_id=self.zone_id,
                    shared=self.shared,
                    **props,
                )
                for (name, props) in self.SMART_FOLDERS.items()
            }

            for folder in self._fetch_folders():

                # Skiping albums having null name, that can happen sometime
                if "albumNameEnc" not in folder["fields"]:
                    continue

                # TODO: Handle subfolders  # pylint: disable=fixme
                if folder["recordName"] in (
                    "----Root-Folder----",
                    "----Project-Root-Folder----",
                ) or (
                    folder["fields"].get("isDeleted")
                    and folder["fields"]["isDeleted"]["value"]
                ):
                    continue

                folder_id = folder["recordName"]
                folder_obj_type = (
                    "CPLContainerRelationNotDeletedByAssetDate:%s" % folder_id
                )
                folder_name = base64.b64decode(
                    folder["fields"].get("albumNameEnc", {}).get("value")
                ).decode("utf-8")
                query_filter = [
                    {
                        "fieldName": "parentId",
                        "comparator": "EQUALS",
                        "fieldValue": {"type": "STRING", "value": folder_id},
                    }
                ]

                album = PhotoAlbum(
                    self.service,
                    folder_name,
                    "CPLContainerRelationLiveByAssetDate",
                    folder_obj_type,
                    "ASCENDING",
                    query_filter,
                    zone_id=self.zone_id,
                    folder=folder,
                )
                self._albums[folder_name] = album

        return self._albums

    def _fetch_folders(self):
        url = f"{self.service.service_endpoint(self.shared)}/records/query?{urlencode(self.service.params)}"
        json_data = json.dumps(
            {"query": {"recordType": "CPLAlbumByPositionLive"}, "zoneID": self.zone_id}
        )

        request = self.service.session.post(
            url, data=json_data, headers={"Content-type": "text/plain"}
        )
        response = request.json()

        return response["records"]

    @property
    def all(self):
        """Returns all photos."""
        return self.albums["All Photos"]


class PhotosService(PhotoLibrary):
    """The 'Photos' iCloud service.

    This also acts as a way to access the user's primary library."""

    def __init__(self, service_root, session, params):
        self.session = session
        self.params = dict(params)
        self._service_root = service_root

        self._service_endpoint = (
            f"{self._service_root}/database/1/com.apple.photos.cloud/production/private"
        )

        self._shared_service_endpoint = (
            f"{self._service_root}/database/1/com.apple.photos.cloud/production/shared"
        )

        self._libraries = None

        self.params.update({"remapEnums": True, "getCurrentSyncToken": True})

        # TODO: Does syncToken ever change?  # pylint: disable=fixme
        # self.params.update({
        #     'syncToken': response['syncToken'],
        #     'clientInstanceId': self.params.pop('clientId')
        # })

        self._photo_assets = {}

        super().__init__(service=self, zone_id={"zoneName": "PrimarySync"})

    def service_endpoint(self, shared=False):
        """Returns the service URL."""
        if self.shared or shared:
            return self._shared_service_endpoint
        return self._service_endpoint

    @property
    def libraries(self):
        if not self._libraries:
            libraries = {}

            url = f"{self._service_endpoint}/zones/list"

            request = self.session.post(
                url, data="{}", headers={"Content-type": "text/plain"}
            )
            response = request.json()
            zones = response["zones"]

            for zone in zones:
                zone_name = zone["zoneID"]["zoneName"]
                libraries[zone_name] = PhotoLibrary(self, zone["zoneID"])

            shared_url = f"{self._shared_service_endpoint}/zones/list"

            request = self.session.post(
                shared_url, data="{}", headers={"Content-type": "text/plain"}
            )

            response = request.json()

            zones = response["zones"]
            for zone in zones:
                zone_name = zone["zoneID"]["zoneName"]
                libraries[zone_name] = PhotoLibrary(self, zone["zoneID"], shared=True)

            self._libraries = libraries

        return self._libraries


class PhotoAlbum:
    """A photo album."""

    def __init__(
        self,
        service,
        name,
        list_type,
        obj_type,
        direction,
        query_filter=None,
        page_size=100,
        zone_id=None,
        folder=None,
        shared=False,
    ):
        self.name = name
        self.service = service
        self.list_type = list_type
        self.obj_type = obj_type
        self.direction = direction
        self.query_filter = query_filter
        self.page_size = page_size

        if zone_id:
            self.zone_id = zone_id
        else:
            self.zone_id = {"zoneName": "PrimarySync"}
        self.shared = shared

        self._len = None
        self._folder = folder or {}

    @property
    def title(self):
        """Gets the album name."""
        return self.name

    @property
    def id(self):
        return self._folder.get("recordName")

    @property
    def created(self):
        created = self._folder.get("created", {}).get("timestamp")
        if created:
            return datetime.fromtimestamp(created / 1000.0)

    def __iter__(self):
        return self.photos

    def __len__(self):
        if self._len is None:
            url = f"{self.service.service_endpoint(self.shared)}/internal/records/query/batch?{urlencode(self.service.params)}"

            request = self.service.session.post(
                url,
                data=json.dumps(
                    {
                        "batch": [
                            {
                                "resultsLimit": 1,
                                "query": {
                                    "filterBy": {
                                        "fieldName": "indexCountID",
                                        "fieldValue": {
                                            "type": "STRING_LIST",
                                            "value": [self.obj_type],
                                        },
                                        "comparator": "IN",
                                    },
                                    "recordType": "HyperionIndexCountLookup",
                                },
                                "zoneWide": True,
                                "zoneID": self.zone_id,
                            }
                        ]
                    }
                ),
                headers={"Content-type": "text/plain"},
            )
            response = request.json()

            self._len = response["batch"][0]["records"][0]["fields"]["itemCount"][
                "value"
            ]

        return self._len

    @property
    def photos(self):
        """Returns the album photos."""
        if self.direction == "DESCENDING":
            offset = len(self) - 1
        else:
            offset = 0
        return self.fetch_records(offset)

    def fetch_records(self, offset, limit=None):
        if not limit:
            limit = len(self)
        total = 0
        while total < limit:
            url = f"{self.service.service_endpoint(self.shared)}/records/query?{urlencode(self.service.params)}"

            request = self.service.session.post(
                url,
                data=json.dumps(
                    self._list_query_gen(
                        offset, self.list_type, self.direction, self.query_filter
                    )
                ),
                headers={"Content-type": "text/plain"},
            )
            response = request.json()

            asset_records = {}
            master_records = []
            for rec in response["records"]:
                if rec["recordType"] == "CPLAsset":
                    master_id = rec["fields"]["masterRef"]["value"]["recordName"]
                    asset_records[master_id] = rec
                elif rec["recordType"] == "CPLMaster":
                    master_records.append(rec)

            master_records_len = len(master_records)
            if master_records_len:
                if self.direction == "DESCENDING":
                    offset = offset - master_records_len
                else:
                    offset = offset + master_records_len

                for master_record in master_records:
                    record_name = master_record["recordName"]
                    total += 1
                    yield PhotoAsset(
                        self.service, master_record, asset_records[record_name]
                    )
            else:
                break

    def _list_query_gen(self, offset, list_type, direction, query_filter=None):
        query = {
            "query": {
                "filterBy": [
                    {
                        "fieldName": "startRank",
                        "fieldValue": {"type": "INT64", "value": offset},
                        "comparator": "EQUALS",
                    },
                    {
                        "fieldName": "direction",
                        "fieldValue": {"type": "STRING", "value": direction},
                        "comparator": "EQUALS",
                    },
                ],
                "recordType": list_type,
            },
            "resultsLimit": self.page_size * 2,
            "desiredKeys": [
                "addedDate",
                "adjustmentRenderType",
                "adjustmentType",
                "assetDate",
                "assetHDRType",
                "assetSubtype",
                "assetSubtypeV2",
                "burstFlags",
                "burstFlagsExt",
                "burstId",
                "captionEnc",
                "codec",
                "contributors",
                "created",
                "customRenderedValue",
                "dataClassType",
                "dateExpunged",
                "duration",
                "extendedDescEnc",
                "filenameEnc",
                "importedBy",
                "importedByBundleIdentifierEnc",
                "importedByDisplayNameEnc",
                "isDeleted",
                "isExpunged",
                "isFavorite",
                "isHidden",
                "isSparsePrivateRecord",
                "itemType",
                "linkedShareRecordName",
                "linkedShareZoneName",
                "linkedShareZoneOwner",
                "locationEnc",
                "locationLatitude",
                "locationLongitude",
                "locationV2Enc",
                "masterRef",
                "mediaMetaDataEnc",
                "mediaMetaDataType",
                "orientation",
                "originalOrientation",
                "recordChangeTag",
                "recordName",
                "recordType",
                "remappedBy",
                "remappedRef",
                "resJPEGFullFileType",
                "resJPEGFullFingerprint",
                "resJPEGFullHeight",
                "resJPEGFullRes",
                "resJPEGFullWidth",
                "resJPEGLargeFileType",
                "resJPEGLargeFingerprint",
                "resJPEGLargeHeight",
                "resJPEGLargeRes",
                "resJPEGLargeWidth",
                "resJPEGMedFileType",
                "resJPEGMedFingerprint",
                "resJPEGMedHeight",
                "resJPEGMedRes",
                "resJPEGMedWidth",
                "resJPEGThumbFileType",
                "resJPEGThumbFingerprint",
                "resJPEGThumbHeight",
                "resJPEGThumbRes",
                "resJPEGThumbWidth",
                "resOriginalAltFileType",
                "resOriginalAltFingerprint",
                "resOriginalAltHeight",
                "resOriginalAltRes",
                "resOriginalAltWidth",
                "resOriginalFileType",
                "resOriginalFingerprint",
                "resOriginalHeight",
                "resOriginalRes",
                "resOriginalVidComplFileType",
                "resOriginalVidComplFingerprint",
                "resOriginalVidComplHeight",
                "resOriginalVidComplRes",
                "resOriginalVidComplWidth",
                "resOriginalWidth",
                "resSidecarFileType",
                "resSidecarFingerprint",
                "resSidecarHeight",
                "resSidecarRes",
                "resSidecarWidth",
                "resVidFullFileType",
                "resVidFullFingerprint",
                "resVidFullHeight",
                "resVidFullRes",
                "resVidFullWidth",
                "resVidHDRMedRes",
                "resVidMedFileType",
                "resVidMedFingerprint",
                "resVidMedHeight",
                "resVidMedRes",
                "resVidMedWidth",
                "resVidSmallFileType",
                "resVidSmallFingerprint",
                "resVidSmallHeight",
                "resVidSmallRes",
                "resVidSmallWidth",
                "timeZoneOffset",
                "vidComplDispScale",
                "vidComplDispValue",
                "vidComplDurScale",
                "vidComplDurValue",
                "vidComplVisibilityState",
                "videoFrameRate",
                "zoneID",
            ],
            "zoneID": self.zone_id,
        }

        if query_filter:
            query["query"]["filterBy"].extend(query_filter)

        return query

    def __str__(self):
        return self.title

    def __repr__(self):
        return f"<{type(self).__name__}: '{self}'>"


class PhotoAsset:
    """A photo."""

    def __init__(self, service, master_record, asset_record):
        self._service = service
        self._master_record = master_record
        self._asset_record = asset_record

        self._versions = None

    ITEM_TYPES = {
        "public.heic": "image",
        "public.jpeg": "image",
        "public.png": "image",
        "com.apple.quicktime-movie": "movie",
    }

    ITEM_TYPE_SUFFIX = {
        "public.heic": "HEIC",
        "public.jpeg": "JPEG",
        "public.png": "PNG",
        "com.apple.quicktime-movie": "MOV",
    }

    PHOTO_VERSION_LOOKUP = {
        "full": "resJPEGFull",
        "large": "resJPEGLarge",
        "medium": "resJPEGMed",
        "thumb": "resJPEGThumb",
        "sidecar": "resSidecar",
        "original": "resOriginal",
        "original_alt": "resOriginalAlt",
        "live": "resOriginalVidCompl",
    }

    VIDEO_VERSION_LOOKUP = {
        "full": "resVidFull",
        "medium": "resVidMed",
        "thumb": "resVidSmall",
        "original": "resOriginal",
        "original_compl": "resOriginalVidCompl",
    }

    @property
    def id(self):
        """Gets the photo id."""
        return self._master_record["recordName"]

    @property
    def filename(self):
        """Gets the photo file name."""
        return base64.b64decode(
            self._master_record["fields"]["filenameEnc"]["value"]
        ).decode("utf-8")

    @property
    def caption(self):
        """Gets the photo caption/title."""
        if self._asset_record["fields"].get("captionEnc"):
            return base64.b64decode(
                self._asset_record["fields"]["captionEnc"]["value"]
            ).decode("utf-8")

    @property
    def description(self):
        """Gets the photo description."""
        if self._asset_record["fields"].get("extendedDescEnc"):
            return base64.b64decode(
                self._asset_record["fields"]["extendedDescEnc"]["value"]
            ).decode("utf-8")

    @property
    def location(self):
        if value := self._asset_record["fields"].get("locationEnc", {}).get("value"):
            try:
                return BPListReader(base64.b64decode(value)).parse()
            except Exception as e:
                try:
                    return BPListReader(value).parse()
                except Exception as e2:
                    print(value, e)
                    return

    @property
    def mediaMetaData(self):
        if (
            value := self._master_record["fields"]
            .get("mediaMetaDataEnc", {})
            .get("value")
        ):
            try:
                return BPListReader(base64.b64decode(value)).parse()
            except Exception as e:
                try:
                    return BPListReader(value).parse()
                except Exception as e2:
                    print(value, e)
                    return

    @property
    def latitude(self):
        if latitude := self._asset_record["fields"].get("locationLatitude"):
            print(latitude)

        if location := self.location:
            return location["lat"][1]
        metadata = self.mediaMetaData
        if metadata and metadata.get("{GPS}"):
            if latitude := metadata["{GPS}"].get("Latitude"):
                return latitude[1]
            print(metadata)
            return None

    @property
    def longitude(self):
        if longitude := self._asset_record["fields"].get("locationLongitude"):
            print(longitude)

        if location := self.location:
            return location["lon"][1]

        metadata = self.mediaMetaData
        if metadata and metadata.get("{GPS}"):
            if longitude := metadata["{GPS}"].get("Longitude"):
                return longitude[1]
            print(metadata)
            return None

    @property
    def isHidden(self):
        if self._asset_record["fields"].get("isHidden"):
            return self._asset_record["fields"].get("isHidden", {})["value"]

    @property
    def isFavorite(self):
        if self._asset_record["fields"].get("isFavorite"):
            return self._asset_record["fields"].get("isFavorite", {})["value"]

    @property
    def size(self):
        """Gets the photo size."""
        return self._master_record["fields"]["resOriginalRes"]["value"]["size"]

    @property
    def created(self):
        """Gets the photo created date."""
        return self.asset_date

    @property
    def asset_date(self):
        """Gets the photo asset date."""
        try:
            return datetime.utcfromtimestamp(
                self._asset_record["fields"]["assetDate"]["value"] / 1000.0
            ).replace(tzinfo=timezone.utc)
        except KeyError:
            return datetime.utcfromtimestamp(0).replace(tzinfo=timezone.utc)

    @property
    def added_date(self):
        """Gets the photo added date."""
        return datetime.utcfromtimestamp(
            self._asset_record["fields"]["addedDate"]["value"] / 1000.0
        ).replace(tzinfo=timezone.utc)

    @property
    def dimensions(self):
        """Gets the photo dimensions."""
        return (
            self._master_record["fields"]["resOriginalWidth"]["value"],
            self._master_record["fields"]["resOriginalHeight"]["value"],
        )

    @property
    def item_type(self):
        item_type = self._master_record["fields"]["itemType"]["value"]
        if item_type in self.ITEM_TYPES:
            return self.ITEM_TYPES[item_type]
        if self.filename.lower().endswith((".heic", ".png", ".jpg", ".jpeg")):
            return "image"
        return "movie"

    @property
    def versions(self):
        """Gets the photo versions."""
        if not self._versions:
            self._versions = {}
            if self.item_type == "movie":
                typed_version_lookup = self.VIDEO_VERSION_LOOKUP
            else:
                typed_version_lookup = self.PHOTO_VERSION_LOOKUP

            # Prefer using adjusted (i.e. user edited) versions of photos if available.
            for record in (self._master_record, self._asset_record):
                for key, prefix in typed_version_lookup.items():
                    if f"{prefix}Res" in record["fields"]:
                        fields = record["fields"]
                        version = {"filename": self.filename}

                        width_entry = fields.get("%sWidth" % prefix)
                        if width_entry:
                            version["width"] = width_entry["value"]
                        else:
                            version["width"] = None

                        height_entry = fields.get("%sHeight" % prefix)
                        if height_entry:
                            version["height"] = height_entry["value"]
                        else:
                            version["height"] = None

                        size_entry = fields.get("%sRes" % prefix)
                        if size_entry:
                            version["size"] = size_entry["value"]["size"]
                            version["url"] = size_entry["value"]["downloadURL"]
                        else:
                            version["size"] = None
                            version["url"] = None

                        type_entry = fields.get("%sFileType" % prefix)
                        type_entry = fields.get("%sFileType" % prefix)
                        if type_entry:
                            version["type"] = type_entry["value"]

                            *base, suffix = self.filename.split(".")
                            base = ".".join(base)
                            suffix = self.ITEM_TYPE_SUFFIX.get(
                                type_entry["value"], suffix
                            )

                            version["filename"] = f"{base}.{suffix}"

                        else:
                            version["type"] = None

                        self._versions[key] = version

        return self._versions

    def download(self, version="original", **kwargs):
        """Returns the photo file."""
        if version not in self.versions:
            return None

        return self._service.session.get(
            self.versions[version]["url"], stream=True, **kwargs
        )

    def delete(self):
        """Deletes the photo."""
        json_data = (
            '{"query":{"recordType":"CheckIndexingState"},'
            '"zoneID":{"zoneName":"PrimarySync"}}'
        )

        json_data = (
            '{"operations":[{'
            '"operationType":"update",'
            '"record":{'
            '"recordName":"%s",'
            '"recordType":"%s",'
            '"recordChangeTag":"%s",'
            '"fields":{"isDeleted":{"value":1}'
            "}}}],"
            '"zoneID":{'
            '"zoneName":"PrimarySync"'
            '},"atomic":true}'
            % (
                self._asset_record["recordName"],
                self._asset_record["recordType"],
                self._master_record["recordChangeTag"],
            )
        )

        params = urlencode(self._service.params)
        url = f"{self.service.service_endpoint()}/records/modify?{params}"

        return self._service.session.post(
            url, data=json_data, headers={"Content-type": "text/plain"}
        )

    def __repr__(self):
        return f"<{type(self).__name__}: id={self.id}>"
