"""Firepit table SQL schemas"""

class Schema(dict):
    '''Firepit table schema'''
    def __init__(self, name, data, unique=None, ignore_conflict=False):
        super().__init__(data)
        self.name = name
        self.unique = unique if unique else []
        self.ignore = ignore_conflict

    def create_stmt(self,
                    mod='',
                    ignore='IGNORE',
                    type_map=None
    ):
        # This is DB-specific, so probably shouldn't be a class method
        if type_map is None:
            type_map = {}
        values = [f'{k} {type_map.get(v, v)}' for k, v in self.items()]
        if self.unique:
            uniques = ', '.join(self.unique)
            values.append(f'UNIQUE({uniques})')
        values = ', '.join(values)
        mod = f'{mod.strip()} ' if mod else ''
        conf = f' ON CONFLICT {ignore}' if self.ignore else ''
        return f'CREATE {mod}TABLE IF NOT EXISTS "{self.name}" ({values}{conf})'


# Common SDOs
IDENTITY_SCHEMA = Schema(
    # Table name
    'identity',
    # Column names and types
    {
        "id": "TEXT UNIQUE",
        "identity_class": "TEXT",
        "name": "TEXT",
        "created": "TEXT",
        "modified": "TEXT"
    }
)

OBSERVED_DATA_SCHEMA = Schema(
    'observed-data',
    {
        "id": "TEXT UNIQUE",
        "created_by_ref": "TEXT",
        "created": "TEXT",
        "modified": "TEXT",
        "first_observed": "TEXT",
        "last_observed": "TEXT",
        "number_observed": "BIGINT"
    }
)


# Internal ("private") tables
METADATA_SCHEMA = Schema(
    "__metadata",
    {
        'name': 'TEXT',
        'value': 'TEXT'
    }
    #TODO:[name]
)


SYMTABLE_SCHEMA = Schema(
    "__symtable",
    {
        'name': 'TEXT',
        'type': 'TEXT',
        'appdata': 'TEXT'
    },
    ['name']
)


QUERIES_SCHEMA = Schema(
    "__queries",
    {
        'sco_id': 'TEXT',
        'query_id': 'TEXT'
    }
    #TODO:(sco_id, query_id)  # Should be unique!
)


COLUMNS_SCHEMA = Schema(
    # Table name
    '__columns',
    # Column names and types
    {
        'otype': 'TEXT',
        'path': 'TEXT',
        'shortname': 'TEXT',
        'dtype': 'TEXT'
    },
    # Constraint
    ('otype', 'path')
)


CONTAINS_SCHEMA = Schema(
    # Table name
    '__contains',
    # Column names and types
    {
        'source_ref': 'TEXT',
        'target_ref': 'TEXT',
        'x_firepit_rank': 'INTEGER',
    },
    # Constraint
    ('source_ref', 'target_ref'),
    # Ignore/do nothing on conflicts
    True
)


REFLIST_SCHEMA = Schema(
    # Table name
    '__reflist',
    # Column names and types
    {
        'ref_name': 'TEXT',
        'source_ref': 'TEXT',
        'target_ref': 'TEXT',
    }
    #TODO:('ref_name', 'source_ref', 'target_ref')
)


INTERNAL_SCHEMAS = [
    METADATA_SCHEMA,
    SYMTABLE_SCHEMA,
    QUERIES_SCHEMA,
    CONTAINS_SCHEMA,
    COLUMNS_SCHEMA,
    IDENTITY_SCHEMA,
    OBSERVED_DATA_SCHEMA,
]
